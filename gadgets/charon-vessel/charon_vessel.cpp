// -----------------------------------------------------------------------------
// Charon Vessel — High-performance file rotation and cleanup
// Secure, atomic operations with cross-device support
// This file is a native tool (vessel), not a god
// -----------------------------------------------------------------------------
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>         
#include <cstdarg>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <deque>
#include <vector>
#include <string>
#include <algorithm>
#include <memory>
#include <unordered_set>
#include <unordered_map>
#include <optional>
#include <future>
#include <stack>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/file.h>
#include <sys/time.h>
#include <inttypes.h>
#include <cerrno>
#include <limits>
#include <climits>    
#include <sys/types.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <array>           

#if defined(__FreeBSD__)
#include <sys/mount.h>     
#elif defined(__linux__)
#include <sys/vfs.h>       
#else
#include <sys/statvfs.h>   
#endif

#if defined(__FreeBSD__)
#include <sys/param.h>
#include <sys/sysctl.h>
#endif

#if defined(__linux__)
#include <sys/syscall.h>
#include <linux/fs.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/capability.h>  
#include <sys/mman.h>
#ifdef HAS_IO_URING
#include <liburing.h>       
#endif
#define HAS_RENAMEAT2 1
#elif defined(__FreeBSD__)

#define HAS_RENAMEAT2 0
#else

#define HAS_RENAMEAT2 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

using namespace std::chrono_literals;


#if defined(__FreeBSD__)
#define PLATFORM_FREEBSD 1
#define PLATFORM_LINUX 0
#elif defined(__linux__)
#define PLATFORM_FREEBSD 0
#define PLATFORM_LINUX 1
#else
#define PLATFORM_FREEBSD 0
#define PLATFORM_LINUX 0
#endif


#ifndef HAS_SYSTEMD
    #if defined(__linux__)
        #define HAS_SYSTEMD 1
    #else
        #define HAS_SYSTEMD 0
    #endif
#endif

#ifndef HAS_LIBCAP
    #if defined(__linux__)
        #define HAS_LIBCAP 1
    #else
        #define HAS_LIBCAP 0
    #endif
#endif


#if HAS_SYSTEMD
#include <systemd/sd-daemon.h>
#include <cstdint>
#endif

// -----------------------------------------------------------------------------
// Charon Vessel — Forward declarations
// -----------------------------------------------------------------------------
struct Config;


extern "C" {
    int charon_get_metrics(char* buf, size_t sz) noexcept;
}

int charon_get_metrics_cpp(char* buf, size_t sz) noexcept;

static void charon_cleanup_aggressive(const std::vector<std::pair<time_t, std::string>>& old_files,
                                     const Config& cfg) noexcept;

// -----------------------------------------------------------------------------
// Charon Vessel — System constants and configuration boundaries
// -----------------------------------------------------------------------------
namespace constants {
    constexpr uint64_t BUFFER_SIZE_MB = 200;
    constexpr uint64_t MIN_BUFFER_SIZE_KB = 16;
    constexpr uint64_t MAX_BUFFER_SIZE_MB = 64;
    constexpr int MAX_COPY_THREADS = 32;
    constexpr int MIN_COPY_THREADS = 1;
    constexpr int DEFAULT_YIELD_EVERY_CHUNKS = 16;
    constexpr size_t DEFAULT_COPY_CHUNK_KB = 128;
    constexpr size_t MAX_DIRECTORY_DEPTH = 100;
    constexpr uint64_t MAX_FILE_SIZE_GB = 10;
    constexpr size_t MAX_DIR_PATH_LENGTH = 1024;
    constexpr size_t MAX_AUDIT_LOG_SIZE = 20000;
    constexpr size_t RING_BUFFER_SIZE = 1024;
    constexpr size_t MAX_FALLBACK_QUEUE = 30000;
    constexpr std::chrono::milliseconds WORKER_SHUTDOWN_POLL_INTERVAL(100);
}

// CLI constants
constexpr const char* PID_DIR = "/var/run/charon";
constexpr const char* PID_FILE = "/var/run/charon/charon.pid";

// -----------------------------------------------------------------------------
// Charon Vessel — RAII wrapper for file descriptors
// -----------------------------------------------------------------------------
class unique_fd {
    int fd_ = -1;
public:
    explicit unique_fd(int fd = -1) noexcept : fd_(fd) {}
    ~unique_fd() { if (fd_ >= 0) ::close(fd_); }
    
    unique_fd(const unique_fd&) = delete;
    unique_fd& operator=(const unique_fd&) = delete;
    
    unique_fd(unique_fd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    unique_fd& operator=(unique_fd&& o) noexcept { 
        if (this != &o) {
            if (fd_ >= 0) ::close(fd_);
            fd_ = o.fd_;
            o.fd_ = -1;
        }
        return *this;
    }
    
    void reset(int fd = -1) noexcept { 
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd; 
    }
    
    int get() const noexcept { return fd_; }
    int release() noexcept { int t = fd_; fd_ = -1; return t; }
    explicit operator bool() const noexcept { return fd_ >= 0; }
};

// -----------------------------------------------------------------------------
// Charon Vessel — Ensures single instance
// -----------------------------------------------------------------------------
class PidFileLock {
    unique_fd fd_;
    std::string path_;
    
public:
    explicit PidFileLock(const std::string& path) : path_(path) {
        fd_.reset(open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644));
        if (!fd_) {
            fprintf(stderr, "ERROR: Cannot open pidfile %s: %s\n", path.c_str(), strerror(errno));
            throw std::runtime_error("pidfile open failed");
        }
        
        // Exclusive flock ensures single instance
        if (flock(fd_.get(), LOCK_EX | LOCK_NB) != 0) {
            if (errno == EWOULDBLOCK) {
                char buf[32];
                ssize_t n = read(fd_.get(), buf, sizeof(buf)-1);
                if (n > 0) {
                    buf[n] = 0;
                    fprintf(stderr, "ERROR: Another instance already running (PID: %s)\n", buf);
                } else {
                    fprintf(stderr, "ERROR: Another instance already running\n");
                }
                exit(1);
            }
            fprintf(stderr, "ERROR: flock failed on pidfile: %s\n", strerror(errno));
            exit(1);
        }
        
        if (ftruncate(fd_.get(), 0) != 0) {
            fprintf(stderr, "WARNING: Failed to truncate pidfile %s: %s\n",
                    path_.c_str(), strerror(errno));
        }
        lseek(fd_.get(), 0, SEEK_SET);
        char pid_str[32];
        snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
        ssize_t written = write(fd_.get(), pid_str, strlen(pid_str));
        (void)written; 
        fsync(fd_.get());
        
        fprintf(stderr, "DEBUG: Acquired pidfile lock: %s\n", path.c_str());
    }
    
    ~PidFileLock() {
        if (fd_) {
            if (ftruncate(fd_.get(), 0) != 0) {
                fprintf(stderr, "WARNING: Failed to truncate pidfile %s on cleanup: %s\n",
                        path_.c_str(), strerror(errno));
            }
            unlink(path_.c_str());
        }
    }
};

static std::unique_ptr<PidFileLock> g_pid_lock;

// -----------------------------------------------------------------------------
// Charon Vessel — Zero-disk temp files for secure copies
// -----------------------------------------------------------------------------
class MemfdTempFile {
    unique_fd fd_;
    std::string name_;
    
public:
    explicit MemfdTempFile(const char* name_prefix = "charon_tmp") noexcept {
        (void)name_prefix;
#ifdef __linux__
        fd_.reset(syscall(SYS_memfd_create, name_prefix, MFD_CLOEXEC | MFD_ALLOW_SEALING));
        if (!fd_) {
            fprintf(stderr, "DEBUG: memfd_create failed: %s, falling back to disk temp\n", strerror(errno));
            return;
        }
        
        fcntl(fd_.get(), F_ADD_SEALS, 
              F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);
        
        static std::atomic<int> counter{0};
        char name[64];
        snprintf(name, sizeof(name), "/memfd:%s_%d_%d", 
                 name_prefix, getpid(), counter.fetch_add(1));
        name_ = name;
        
        fprintf(stderr, "DEBUG: Created memfd temp file: %s\n", name_.c_str());
#endif
    }
    
    bool valid() const noexcept { return static_cast<bool>(fd_); }
    int fd() const noexcept { return fd_.get(); }
    const std::string& name() const noexcept { return name_; }
};

// -----------------------------------------------------------------------------
// Charon Vessel — Unified logging with daemon support
// -----------------------------------------------------------------------------
static std::mutex g_log_mutex;
static std::atomic<bool> g_is_daemon{false};

static void charon_log_output(const char* module, const char* level, const char* fmt, ...) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    
    char buffer[2048];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    
    if (len <= 0) return;
    
    int syslog_level;
    if (strcmp(level, "ERROR") == 0) syslog_level = LOG_ERR;
    else if (strcmp(level, "WARN") == 0) syslog_level = LOG_WARNING;
    else if (strcmp(level, "INFO") == 0) syslog_level = LOG_INFO;
    else syslog_level = LOG_DEBUG;
    
    char full_msg[4096];
    snprintf(full_msg, sizeof(full_msg), "[%s] %s", module, buffer);
    syslog(syslog_level, "[%s] %s", level, full_msg);
    
    if (!g_is_daemon.load(std::memory_order_relaxed)) {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        struct tm tm_time{};
        localtime_r(&t, &tm_time);
        
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_time);
        
        fprintf(stderr, "[%s][%s][%s] %s\n", level, timestamp, module, buffer);
        fflush(stderr);
    }
}

#define CHARON_LOG_INFO(module, ...)   charon_log_output(module, "INFO",  __VA_ARGS__)
#define CHARON_LOG_ERROR(module, ...)  charon_log_output(module, "ERROR", __VA_ARGS__)
#define CHARON_LOG_WARN(module, ...)   charon_log_output(module, "WARN",  __VA_ARGS__)
#define CHARON_LOG_DEBUG(module, ...)  charon_log_output(module, "DEBUG", __VA_ARGS__)

// -----------------------------------------------------------------------------
// Charon Vessel — Performance monitoring across all modules
// -----------------------------------------------------------------------------
struct Metrics {
    std::atomic<uint64_t> rotated_total{0};
    std::atomic<uint64_t> cross_device_moves{0};
    std::atomic<uint64_t> cleanup_dirs{0};
    std::atomic<uint64_t> cleanup_files{0};
    std::atomic<uint64_t> temp_gc_removed{0};
    std::atomic<uint64_t> errors{0};
    std::atomic<uint64_t> out_of_space{0};
    std::atomic<uint64_t> scan_iterations{0};
    std::atomic<uint64_t> files_scanned{0};
    std::atomic<uint64_t> backpressure_events{0};
    std::atomic<int>      active_copies{0};
    std::atomic<int>      queued_tasks{0};
    std::atomic<int>      current_copy_threads{8};
    std::atomic<uint64_t> copy_file_range_calls{0};
    std::atomic<uint64_t> fallback_copy_calls{0};
    std::atomic<uint64_t> copy_bytes_total{0};
    std::atomic<uint64_t> queue_full_rejections{0};
    std::atomic<uint64_t> copy_operations_time_ms{0};
    std::atomic<uint64_t> symlinks_skipped{0};
    std::atomic<uint64_t> hardlinks_skipped{0};
    std::atomic<uint64_t> oversized_files_skipped{0};
    std::atomic<uint64_t> security_errors{0};
    std::atomic<uint64_t> invalid_paths_rejected{0};
    std::atomic<uint64_t> integer_overflow_checks{0};
    std::atomic<uint64_t> buffer_clears{0};
    std::atomic<uint64_t> fsync_calls{0};
    std::atomic<uint64_t> io_uring_ops{0};
    std::atomic<uint64_t> adaptive_buffer_adjustments{0};
    std::atomic<uint64_t> atomic_rename_success{0};
    std::atomic<uint64_t> atomic_rename_failed{0};
};

static Metrics charon_metrics;
static std::atomic<int> g_rotation_failures{0};

// -----------------------------------------------------------------------------
// Charon Vessel — Environment-based configuration
// -----------------------------------------------------------------------------
struct Config {
    std::string fresh_path = "/mnt/x/nekhebet/charon/fresh";
    std::string archive_root = "/mnt/x/nekhebet/charon/archive";
    size_t max_fresh = 75;
    int rotation_sec = 7;
    int cleanup_min = 30;
    uint64_t disk_limit_pct = 84;
    int mtime_tolerance_sec = 1;
    size_t copy_chunk_kb = constants::DEFAULT_COPY_CHUNK_KB;
    int temp_gc_age_sec = 600;
    int cleanup_batch = 100;
    int max_age_days = 1825;
    int copy_threads = 8;
    bool adaptive_throttle = true;
    int yield_every_chunks = constants::DEFAULT_YIELD_EVERY_CHUNKS;
    bool use_copy_file_range = true;
    bool use_sendfile = false;
    bool enable_io_uring = false;
    uint64_t max_file_size_gb = constants::MAX_FILE_SIZE_GB;
    bool secure_buffer_clear = false;
    bool enable_audit_log = true;
    bool minimize_fsync = false;
    uint64_t min_buffer_size_kb = constants::MIN_BUFFER_SIZE_KB;
    uint64_t max_buffer_size_mb = constants::MAX_BUFFER_SIZE_MB;
    bool enable_adaptive_buffer = true;
    bool use_syslog = true;
    bool daemonize = true;
    std::string chroot_path;
    std::string run_as_user = "charon";
    bool use_xattr_index = true;
    bool enable_fast_scan = true;
    bool verbose_logging = false;
    bool use_memfd = true;
    
    uint64_t buffer_size_bytes() const noexcept {
        return constants::BUFFER_SIZE_MB * 1024 * 1024;
    }
    
    uint64_t max_file_size_bytes() const noexcept {
        if (max_file_size_gb > 1024) return std::numeric_limits<uint64_t>::max();
        return max_file_size_gb * 1024ULL * 1024 * 1024;
    }
    
    uint64_t adaptive_buffer_size(uint64_t file_size) const noexcept {
        if (!enable_adaptive_buffer) {
            return std::min<uint64_t>(buffer_size_bytes(), max_buffer_size_mb * 1024ULL * 1024);
        }
        
        uint64_t target_size = std::min<uint64_t>(file_size / 4, max_buffer_size_mb * 1024ULL * 1024);
        target_size = std::max<uint64_t>(target_size, min_buffer_size_kb * 1024ULL);
        
        uint64_t power_of_two = 1;
        while (power_of_two * 2 <= target_size) {
            power_of_two *= 2;
        }
        
        return power_of_two;
    }
};

static std::shared_ptr<const Config> charon_load_config_from_env() noexcept {
    auto cfg = std::make_shared<Config>();

    if (const char* v = getenv("FRESH_PATH")) cfg->fresh_path = v;
    if (const char* v = getenv("ARCHIVE_ROOT")) cfg->archive_root = v;
    if (const char* v = getenv("CHROOT_PATH")) cfg->chroot_path = v;
    if (const char* v = getenv("RUN_AS_USER")) cfg->run_as_user = v;

    auto safe_stoull = [](const char* v, uint64_t default_val) -> uint64_t {
        if (!v) return default_val;
        try { return std::stoull(v); } catch(...) { return default_val; }
    };

    auto safe_stoi = [](const char* v, int default_val) -> int {
        if (!v) return default_val;
        try { return std::stoi(v); } catch(...) { return default_val; }
    };

    auto parse_bool = [](const char* v, bool default_val) -> bool {
        if (!v) return default_val;
        return strcmp(v, "0") != 0 && strcmp(v, "false") != 0 && strcmp(v, "no") != 0;
    };

    cfg->max_fresh = safe_stoull(getenv("MAX_FRESH"), cfg->max_fresh);
    cfg->rotation_sec = safe_stoi(getenv("ROTATION_SEC"), cfg->rotation_sec);
    cfg->cleanup_min = safe_stoi(getenv("CLEANUP_MIN"), cfg->cleanup_min);
    cfg->disk_limit_pct = safe_stoull(getenv("DISK_LIMIT_PCT"), cfg->disk_limit_pct);
    cfg->mtime_tolerance_sec = safe_stoi(getenv("MTIME_TOLERANCE"), cfg->mtime_tolerance_sec);
    cfg->copy_chunk_kb = safe_stoull(getenv("COPY_CHUNK_KB"), cfg->copy_chunk_kb);
    cfg->yield_every_chunks = safe_stoi(getenv("YIELD_EVERY_CHUNKS"), cfg->yield_every_chunks);
    cfg->temp_gc_age_sec = safe_stoi(getenv("TEMP_GC_SEC"), cfg->temp_gc_age_sec);
    cfg->cleanup_batch = safe_stoi(getenv("CLEANUP_BATCH"), cfg->cleanup_batch);
    cfg->max_age_days = safe_stoi(getenv("MAX_AGE_DAYS"), cfg->max_age_days);
    cfg->copy_threads = std::max(1, safe_stoi(getenv("COPY_THREADS"), cfg->copy_threads));
    cfg->max_file_size_gb = safe_stoull(getenv("MAX_FILE_SIZE_GB"), cfg->max_file_size_gb);
    cfg->min_buffer_size_kb = safe_stoull(getenv("MIN_BUFFER_KB"), cfg->min_buffer_size_kb);
    cfg->max_buffer_size_mb = safe_stoull(getenv("MAX_BUFFER_MB"), cfg->max_buffer_size_mb);

    cfg->adaptive_throttle = parse_bool(getenv("ADAPTIVE_THROTTLE"), cfg->adaptive_throttle);
    cfg->use_copy_file_range = parse_bool(getenv("USE_COPY_FILE_RANGE"), cfg->use_copy_file_range);
    cfg->use_sendfile = parse_bool(getenv("USE_SENDFILE"), cfg->use_sendfile);
    cfg->verbose_logging = parse_bool(getenv("VERBOSE_LOGGING"), cfg->verbose_logging);
    cfg->secure_buffer_clear = parse_bool(getenv("SECURE_BUFFER_CLEAR"), cfg->secure_buffer_clear);
    cfg->enable_audit_log = parse_bool(getenv("ENABLE_AUDIT_LOG"), cfg->enable_audit_log);
    cfg->minimize_fsync = parse_bool(getenv("MINIMIZE_FSYNC"), cfg->minimize_fsync);
    cfg->enable_io_uring = parse_bool(getenv("ENABLE_IO_URING"), cfg->enable_io_uring);
    cfg->enable_adaptive_buffer = parse_bool(getenv("ADAPTIVE_BUFFER"), cfg->enable_adaptive_buffer);
    cfg->use_syslog = parse_bool(getenv("USE_SYSLOG"), cfg->use_syslog);
    cfg->daemonize = parse_bool(getenv("DAEMONIZE"), cfg->daemonize);
    cfg->use_xattr_index = parse_bool(getenv("USE_XATTR_INDEX"), cfg->use_xattr_index);
    cfg->enable_fast_scan = parse_bool(getenv("ENABLE_FAST_SCAN"), cfg->enable_fast_scan);
    cfg->use_memfd = parse_bool(getenv("USE_MEMFD"), cfg->use_memfd);

#if PLATFORM_FREEBSD
    cfg->use_copy_file_range = true;
    cfg->use_sendfile = false;
    cfg->enable_io_uring = false;
    cfg->enable_fast_scan = false;  // xattr not supported on FreeBSD
#endif

    // Validation
    if (cfg->fresh_path.empty() || cfg->archive_root.empty()) {
        CHARON_LOG_ERROR("charon", "Configuration error: paths cannot be empty");
        return nullptr;
    }

    if (cfg->fresh_path[0] != '/' || cfg->archive_root[0] != '/') {
        CHARON_LOG_ERROR("charon", "Configuration error: paths must be absolute");
        return nullptr;
    }

    // Clamping
    if (cfg->disk_limit_pct > 100) cfg->disk_limit_pct = 100;
    if (cfg->max_fresh < 1) cfg->max_fresh = 1;
    if (cfg->rotation_sec < 1) cfg->rotation_sec = 1;
    if (cfg->cleanup_min < 1) cfg->cleanup_min = 1;
    if (cfg->max_file_size_gb < 1) cfg->max_file_size_gb = 1;
    if (cfg->max_file_size_gb > 100) cfg->max_file_size_gb = 100;
    if (cfg->copy_chunk_kb < 4) cfg->copy_chunk_kb = 4;
    if (cfg->copy_chunk_kb > 16384) cfg->copy_chunk_kb = 16384;
    if (cfg->min_buffer_size_kb < 4) cfg->min_buffer_size_kb = 4;
    if (cfg->max_buffer_size_mb > 1024) cfg->max_buffer_size_mb = 1024;

    return cfg;
}

// Helper functions for string operations (C++17 compatible)

static bool charon_string_ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && 
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Replace std::atomic<std::shared_ptr<const Config>> with mutex
class ConfigHolder {
    mutable std::mutex mtx_;
    std::shared_ptr<const Config> ptr_;
    
public:
    void store(std::shared_ptr<const Config> p) noexcept { 
        std::lock_guard<std::mutex> lk(mtx_); 
        ptr_ = std::move(p);
    }
    
    std::shared_ptr<const Config> load() const noexcept { 
        std::lock_guard<std::mutex> lk(mtx_);
        return ptr_;
    }
};

static ConfigHolder charon_config;

// -----------------------------------------------------------------------------
// Charon Vessel — Signal handling for graceful shutdown/reload
// -----------------------------------------------------------------------------
static std::atomic<bool> charon_shutdown{false};
static std::atomic<bool> charon_reload{false};

static void charon_safe_signal_handler(int sig, siginfo_t* info, void* context) noexcept {
    (void)info;
    (void)context;
   
    if (sig == SIGHUP) {
        charon_reload.store(true, std::memory_order_release);
        return;
    }
   
    // SIGTERM / SIGINT
    bool already_shutting_down = charon_shutdown.exchange(true, std::memory_order_acq_rel);
    if (!already_shutting_down) {
        CHARON_LOG_INFO("charon", "Received signal %d, initiating shutdown", sig);
    }
}

static void charon_install_signal_handlers() noexcept {
    struct sigaction sa{};
    sa.sa_sigaction = charon_safe_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
    
    signal(SIGPIPE, SIG_IGN);
}

static void charon_block_signals_in_worker_threads() noexcept {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
}

// -----------------------------------------------------------------------------
// Charon Vessel — Security: Privilege dropping and isolation
// -----------------------------------------------------------------------------
static bool charon_drop_capabilities() noexcept {
#ifdef __linux__
    cap_t caps = cap_get_proc();
    if (!caps) return false;
    
    cap_value_t cap_list[] = {
        CAP_DAC_OVERRIDE,
        CAP_DAC_READ_SEARCH,
        CAP_SYS_ADMIN,
        CAP_SYS_RAWIO,
        CAP_NET_ADMIN,
        CAP_SYS_PTRACE
    };
    
    cap_set_flag(caps, CAP_EFFECTIVE, sizeof(cap_list)/sizeof(cap_list[0]), cap_list, CAP_CLEAR);
    cap_set_flag(caps, CAP_PERMITTED, sizeof(cap_list)/sizeof(cap_list[0]), cap_list, CAP_CLEAR);
    cap_set_flag(caps, CAP_INHERITABLE, sizeof(cap_list)/sizeof(cap_list[0]), cap_list, CAP_CLEAR);
    
    if (cap_set_proc(caps) != 0) {
        cap_free(caps);
        return false;
    }
    
    cap_free(caps);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    
    CHARON_LOG_INFO("charon", "Dropped all dangerous capabilities");
    return true;
#else
    return true;
#endif
}

static bool charon_drop_privileges(const Config& cfg) noexcept {
    if (getuid() == 0 && !cfg.run_as_user.empty()) {
        struct passwd* pw = getpwnam(cfg.run_as_user.c_str());
        if (!pw) {
            CHARON_LOG_ERROR("charon", "User '%s' not found", cfg.run_as_user.c_str());
            return false;
        }
        
        if (!cfg.chroot_path.empty()) {
            if (chroot(cfg.chroot_path.c_str()) != 0) {
                CHARON_LOG_ERROR("charon", "chroot to %s failed: %s", cfg.chroot_path.c_str(), strerror(errno));
                return false;
            }
            CHARON_LOG_INFO("charon", "Chrooted to %s", cfg.chroot_path.c_str());
        }
        
        if (setgid(pw->pw_gid) != 0) {
            CHARON_LOG_ERROR("charon", "setgid failed: %s", strerror(errno));
            return false;
        }
        
        if (setuid(pw->pw_uid) != 0) {
            CHARON_LOG_ERROR("charon", "setuid failed: %s", strerror(errno));
            return false;
        }
        
        if (!charon_drop_capabilities()) {
            CHARON_LOG_WARN("charon", "Failed to drop capabilities, continuing with reduced security");
        }
        
        CHARON_LOG_INFO("charon", "Dropped privileges to UID=%d GID=%d", pw->pw_uid, pw->pw_gid);
    }
    
    return true;
}

// -----------------------------------------------------------------------------
// Charon Vessel — Integration with systemd for status notifications
// -----------------------------------------------------------------------------
#ifdef __linux__
#include <systemd/sd-daemon.h>
#include <cstdio>         
#include <cstdlib>       
#include <cstdint>

class SystemdNotifier {
    std::atomic<bool> ready_{false};

public:
    void notify_ready() noexcept {
        if (ready_.exchange(true)) return;

        char buf[256];
        snprintf(buf, sizeof(buf),
                 "READY=1\n"
                 "STATUS=Charon service operational\n"
                 "MAINPID=%lu",
                 (unsigned long)getpid());

        sd_notify(0, buf);

        const char* watchdog_usec = getenv("WATCHDOG_USEC");
        if (watchdog_usec) {
            try {
                uint64_t usec = std::stoull(watchdog_usec);
                if (usec > 0) {
                    start_watchdog_pinger(usec / 2);
                }
            } catch (...) {

            }
        }
    }

    void notify_reloading() noexcept {
        sd_notify(0, "RELOADING=1\nSTATUS=Reloading configuration");
    }

    void notify_stopping() noexcept {
        sd_notify(0, "STOPPING=1\nSTATUS=Shutting down");
    }

    void update_status(const char* status) noexcept {
        char buf[256];
        snprintf(buf, sizeof(buf), "STATUS=%s", status);
        sd_notify(0, buf);          
    }

private:
    void start_watchdog_pinger(uint64_t interval_usec) {
        std::thread([interval_usec] {
            while (!charon_shutdown.load(std::memory_order_acquire)) {
                std::this_thread::sleep_for(std::chrono::microseconds(interval_usec));
                sd_notify(0, "WATCHDOG=1");
            }
        }).detach();
    }
};

static SystemdNotifier g_systemd_notifier;
#endif

// -----------------------------------------------------------------------------
// Charon Vessel — Reliable I/O with retries
// -----------------------------------------------------------------------------
static ssize_t charon_safe_read(int fd, void* buf, size_t count) noexcept {
    ssize_t total = 0;
    
    while (total < static_cast<ssize_t>(count)) {
        ssize_t res = read(fd, static_cast<char*>(buf) + total, count - total);
        
        if (res > 0) {
            total += res;
        } else if (res == 0) {
            break;
        } else {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
                continue;
            }
            return -1;
        }
    }
    
    return total;
}

static ssize_t charon_safe_write(int fd, const void* buf, size_t count) noexcept {
    ssize_t total = 0;
    
    while (total < static_cast<ssize_t>(count)) {
        ssize_t res = write(fd, static_cast<const char*>(buf) + total, count - total);
        
        if (res > 0) {
            total += res;
        } else if (res < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
                continue;
            }
            return -1;
        } else {
            if (count > 0) {
                errno = EPIPE;
                return -1;
            }
            break;
        }
    }
    
    return total;
}

// -----------------------------------------------------------------------------
// Charon Vessel — Security: Path validation
// -----------------------------------------------------------------------------
static bool charon_contains_path_traversal(const std::string& path) noexcept {
    if (path.find("..") != std::string::npos) {
        return true;
    }
    
    size_t slash_count = std::count(path.begin(), path.end(), '/');
    if (slash_count > 64) {
        return true;
    }
    
    if (path.find("/./") != std::string::npos) {
        return true;
    }
    
    if (charon_string_ends_with(path, "/.") || path.find("//") != std::string::npos) {
        return true;
    }
    
    return false;
}

static bool charon_validate_path_length(const std::string& path) noexcept {
    if (path.length() >= PATH_MAX - 100) {
        ++charon_metrics.security_errors;
        CHARON_LOG_ERROR("security", "Path length exceeds safe limit: %zu bytes", path.length());
        return false;
    }
    
    if (path.find('\0') != std::string::npos) {
        ++charon_metrics.security_errors;
        CHARON_LOG_ERROR("security", "Null byte in path (possible injection)");
        return false;
    }
    
    return true;
}

// -----------------------------------------------------------------------------
// Secure directory creation with symlink protection
// -----------------------------------------------------------------------------
static int charon_mkdir_p_safe(const std::string& path, mode_t mode = 0755) noexcept {
    if (path.empty() || path == "/" || path == ".") {
        errno = EINVAL;
        return -1;
    }

    if (!charon_validate_path_length(path) || charon_contains_path_traversal(path)) {
        errno = EINVAL;
        return -1;
    }

    std::string current;
    for (size_t i = 0; i < path.size(); ++i) {
        if (path[i] == '/' && i > 0) {
            current = path.substr(0, i);
            struct stat st;
            if (stat(current.c_str(), &st) == 0) {
                if (!S_ISDIR(st.st_mode)) {
                    errno = ENOTDIR;
                    return -1;
                }
            } else if (errno == ENOENT) {
                if (mkdir(current.c_str(), mode) != 0 && errno != EEXIST) {
                    return -1;
                }
            } else {
                return -1;
            }
        }
    }

    // Final directory
    if (mkdir(path.c_str(), mode) != 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

// -----------------------------------------------------------------------------
// Charon Vessel — Optimized scanning with xattr
// -----------------------------------------------------------------------------
#ifdef __linux__
#include <sys/xattr.h>
#endif

class FreshFileIndex {
private:
    struct FileEntry {
        time_t mtime;
        uint64_t size;
        ino_t inode;
    };
    
    std::unordered_map<std::string, FileEntry> index_;
    mutable std::mutex index_mtx_;
    std::atomic<bool> enabled_{false};
    
    static constexpr const char* XATTR_SCAN_TIME = "user.charon.scan_time";
    
public:
    void enable(bool state) noexcept { enabled_.store(state); }
    
    bool is_file_unchanged(const std::string& path, const struct stat& st) noexcept {
        if (!enabled_.load()) return false;
        
        std::lock_guard<std::mutex> lock(index_mtx_);
        auto it = index_.find(path);
        if (it == index_.end()) return false;
        
        const auto& entry = it->second;
        return entry.mtime == st.st_mtime && 
               entry.size == static_cast<uint64_t>(st.st_size) &&
               entry.inode == st.st_ino;
    }
    
    void update_index(const std::string& path, const struct stat& st) noexcept {
        if (!enabled_.load()) return;
        
        std::lock_guard<std::mutex> lock(index_mtx_);
        index_[path] = {st.st_mtime, static_cast<uint64_t>(st.st_size), st.st_ino};
        
#ifdef __linux__
        time_t now = time(nullptr);
        syscall(SYS_fsetxattr, AT_FDCWD, path.c_str(), XATTR_SCAN_TIME, &now, sizeof(now), 0);
#endif
    }
    
    void cleanup_old_entries(const std::string& fresh_path) noexcept {
        std::lock_guard<std::mutex> lock(index_mtx_);
        
        auto it = index_.begin();
        while (it != index_.end()) {
            struct stat st;
            if (stat(it->first.c_str(), &st) != 0 || 
                it->first.compare(0, fresh_path.length(), fresh_path) != 0) {
                it = index_.erase(it);
            } else {
                ++it;
            }
        }
    }
};

static FreshFileIndex g_fresh_index;

// -----------------------------------------------------------------------------
// Charon Vessel — Efficient directory scanning
// -----------------------------------------------------------------------------
static std::vector<std::pair<time_t, std::string>> 
charon_scan_fresh_efficient(const std::string& path) noexcept {
    CHARON_LOG_DEBUG("charon", "Scanning directory efficiently: %s", path.c_str());
    
    std::vector<std::pair<time_t, std::string>> files;
    
#ifdef __linux__
    unique_fd dir_fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_PATH));
#else
    unique_fd dir_fd(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
#endif
    if (!dir_fd) {
        CHARON_LOG_ERROR("charon", "Failed to open directory: %s : %s", path.c_str(), strerror(errno));
        return files;
    }
    
    DIR* dir = fdopendir(dir_fd.get());
    if (!dir) {
        CHARON_LOG_ERROR("charon", "fdopendir failed: %s", strerror(errno));
        return files;
    }
    
    dir_fd.release();
    
    struct dirent* de;
    while ((de = readdir(dir)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        
        struct stat st{};
        if (fstatat(dirfd(dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            CHARON_LOG_WARN("charon", "fstatat failed for %s/%s: %s", path.c_str(), de->d_name, strerror(errno));
            continue;
        }
        
        if (!S_ISREG(st.st_mode)) continue;
        
        std::string full = path + "/" + de->d_name;
        
        if (charon_contains_path_traversal(full) || !charon_validate_path_length(full)) {
            ++charon_metrics.invalid_paths_rejected;
            CHARON_LOG_WARN("security", "Skipping file with invalid path: %s", full.c_str());
            continue;
        }
        
        if (g_fresh_index.is_file_unchanged(full, st)) {
            continue;
        }
        
        files.emplace_back(st.st_mtime, full);
        g_fresh_index.update_index(full, st);
    }
    
    closedir(dir);
    
    CHARON_LOG_DEBUG("charon", "Scanned %zu files from %s", files.size(), path.c_str());
    return files;
}

// -----------------------------------------------------------------------------
// Enhanced symlink and TOCTOU protection for file operations
// -----------------------------------------------------------------------------
static bool charon_safe_open_no_follow(const std::string& path, int flags,
                               struct stat* st_out = nullptr) noexcept {
    unique_fd fd(open(path.c_str(), flags | O_CLOEXEC));
    if (!fd) {
        if (errno == ELOOP) {
            ++charon_metrics.symlinks_skipped;
            CHARON_LOG_WARN("security", "Symlink detected and blocked: %s", path.c_str());
        }
        return false;
    }

    struct stat fst{};
    if (fstat(fd.get(), &fst) != 0) {
        return false;
    }

    struct stat lst{};
    if (lstat(path.c_str(), &lst) != 0) {
        return false;
    }

    // Manual symlink check (works on both Linux and FreeBSD)
    if (fst.st_ino != lst.st_ino || fst.st_dev != lst.st_dev) {
        ++charon_metrics.security_errors;
        CHARON_LOG_ERROR("security", "Symlink attack detected (inode/dev mismatch): %s", path.c_str());
        return false;
    }

    if (S_ISLNK(lst.st_mode)) {
        ++charon_metrics.security_errors;
        CHARON_LOG_ERROR("security", "Symlink attack detected: %s", path.c_str());
        return false;
    }

    if (st_out) {
        *st_out = fst;
    }

    return true;
}

// -----------------------------------------------------------------------------
// Charon Vessel — Atomic renames with kernel features
// -----------------------------------------------------------------------------
static bool charon_atomic_file_replace(const std::string& target, const std::string& temp_path) noexcept {
#if HAS_RENAMEAT2 && defined(RENAME_NOREPLACE)
    if (syscall(SYS_renameat2, AT_FDCWD, temp_path.c_str(),
                AT_FDCWD, target.c_str(), RENAME_NOREPLACE) == 0) {
        CHARON_LOG_DEBUG("charon", "Atomic renameat2 with RENAME_NOREPLACE succeeded");
        return true;
    }
    
    if (errno == ENOSYS || errno == EINVAL) {
#endif
        if (rename(temp_path.c_str(), target.c_str()) == 0) {
            CHARON_LOG_DEBUG("charon", "Atomic rename succeeded");
            return true;
        }
#if HAS_RENAMEAT2 && defined(RENAME_NOREPLACE)
    }
#endif
    
    CHARON_LOG_WARN("charon", "Atomic rename failed: %s -> %s: %s", 
             temp_path.c_str(), target.c_str(), strerror(errno));
    return false;
}

// -----------------------------------------------------------------------------
// Adaptive buffer management for copy operations
// -----------------------------------------------------------------------------
static thread_local std::vector<char> g_copy_buffer;
static thread_local uint64_t g_last_file_size = 0;

static void charon_ensure_adaptive_copy_buffer(uint64_t file_size) {
    auto cfg_ptr = charon_config.load();
    if (!cfg_ptr) return;
    
    const Config& cfg = *cfg_ptr;
    
    uint64_t target_size = cfg.adaptive_buffer_size(file_size);
    
    if (g_copy_buffer.size() != target_size || g_last_file_size != file_size) {
        g_copy_buffer.resize(target_size);
        g_last_file_size = file_size;
        ++charon_metrics.adaptive_buffer_adjustments;
        CHARON_LOG_DEBUG("charon", "Adaptive buffer resize: %zu bytes for file %lu bytes", 
                 target_size, file_size);
    }
}

static void charon_secure_clear_buffer() noexcept {
    auto cfg_ptr = charon_config.load();
    if (!cfg_ptr || !cfg_ptr->secure_buffer_clear) return;
    
    if (!g_copy_buffer.empty()) {
        memset(g_copy_buffer.data(), 0, g_copy_buffer.size());
        ++charon_metrics.buffer_clears;
        CHARON_LOG_DEBUG("security", "Securely cleared copy buffer");
    }
}

// -----------------------------------------------------------------------------
// Destination path validation with security checks
// -----------------------------------------------------------------------------
static bool charon_validate_destination_path(const std::string& dst_path,
                                     const std::string& archive_root) noexcept {
    if (dst_path.empty() || archive_root.empty()) {
        return false;
    }
    
    if (charon_contains_path_traversal(dst_path) || !charon_validate_path_length(dst_path)) {
        ++charon_metrics.invalid_paths_rejected;
        return false;
    }
    
    // check archive_root
    if (dst_path.compare(0, archive_root.length(), archive_root) != 0) {
        ++charon_metrics.invalid_paths_rejected;
        return false;
    }
    
#if PLATFORM_FREEBSD
    // FreeBSD
    CHARON_LOG_DEBUG("charon", "FreeBSD: Skipping realpath validation for: %s", dst_path.c_str());
    return true;
#else
    // Linux
    char resolved[PATH_MAX];
    if (realpath(dst_path.c_str(), resolved) == nullptr) {
        ++charon_metrics.invalid_paths_rejected;
        CHARON_LOG_WARN("security", "realpath failed for %s: %s", dst_path.c_str(), strerror(errno));
        return false;
    }
    
    if (strncmp(resolved, archive_root.c_str(), archive_root.length()) != 0 ||
        (resolved[archive_root.length()] != '\0' && 
         resolved[archive_root.length()] != '/')) {
        ++charon_metrics.invalid_paths_rejected;
        CHARON_LOG_WARN("security", "Path resolves outside archive root: %s -> %s", 
                 dst_path.c_str(), resolved);
        return false;
    }
    
    return true;
#endif
}

// -----------------------------------------------------------------------------
// Source file validation with security and integrity checks
// -----------------------------------------------------------------------------
static bool charon_validate_source_file(const std::string& src_path, 
                                 unique_fd& src_fd, 
                                 struct stat& st) noexcept {
    auto cfg_ptr = charon_config.load();
    if (!cfg_ptr) return false;
    
    const Config& cfg = *cfg_ptr;
    
    if (charon_contains_path_traversal(src_path) || !charon_validate_path_length(src_path)) {
        ++charon_metrics.invalid_paths_rejected;
        return false;
    }
    
    if (!charon_safe_open_no_follow(src_path, O_RDONLY, &st)) {
        if (errno == ELOOP) {
            ++charon_metrics.symlinks_skipped;
            CHARON_LOG_WARN("security", "Symlink detected: %s", src_path.c_str());
        } else {
            ++charon_metrics.errors;
            CHARON_LOG_ERROR("charon", "open(src) failed: %s : %s", src_path.c_str(), strerror(errno));
        }
        return false;
    }
    
    int fd = open(src_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    src_fd.reset(fd);
    
    if (flock(src_fd.get(), LOCK_EX | LOCK_NB) != 0) {
        int e = errno;
        if (e == EWOULDBLOCK) {
            CHARON_LOG_WARN("charon", "source file is locked (skipping): %s", src_path.c_str());
            return false;
        }
        
        if (e != EINVAL && e != EOPNOTSUPP && e != ENOLCK) {
            CHARON_LOG_WARN("charon", "flock failed for %s: %s", src_path.c_str(), strerror(e));
        }
    }
    
    if (!S_ISREG(st.st_mode)) {
        ++charon_metrics.errors;
        CHARON_LOG_WARN("charon", "src not regular: %s", src_path.c_str());
        return false;
    }
    
    uint64_t file_size = static_cast<uint64_t>(st.st_size);
    if (file_size > cfg.max_file_size_bytes()) {
        ++charon_metrics.oversized_files_skipped;
        CHARON_LOG_WARN("charon", "Skipping oversized file: %s (%lu bytes > %lu GB limit)", 
                src_path.c_str(), 
                static_cast<unsigned long>(st.st_size),
                cfg.max_file_size_gb);
        return false;
    }
    
    if (st.st_nlink > 1) {
        ++charon_metrics.hardlinks_skipped;
        CHARON_LOG_WARN("charon", "Skipping file %s: Has %lu hard links", 
                src_path.c_str(), 
                static_cast<unsigned long>(st.st_nlink));
        return false;
    }
    
    CHARON_LOG_DEBUG("charon", "Validated source file: %s (%lu bytes)", 
              src_path.c_str(), static_cast<unsigned long>(st.st_size));
    return true;
}

// -----------------------------------------------------------------------------
// Charon Vessel — High-performance copying with fallbacks
// -----------------------------------------------------------------------------
#ifdef HAS_IO_URING
static bool charon_copy_fd_io_uring(int src_fd, int dst_fd, uint64_t file_size) noexcept {
    struct io_uring ring;
    if (io_uring_queue_init(32, &ring, 0) < 0) {
        CHARON_LOG_DEBUG("charon", "io_uring init failed, falling back");
        return false;
    }
    
    uint64_t remaining = file_size;
    off_t src_offset = 0;
    off_t dst_offset = 0;
    
    while (remaining > 0 && !charon_shutdown.load(std::memory_order_acquire)) {
        size_t chunk_size = std::min(static_cast<size_t>(remaining), 
                                    static_cast<size_t>(1 * 1024 * 1024));
        
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            io_uring_submit(&ring);
            sqe = io_uring_get_sqe(&ring);
            if (!sqe) break;
        }
        
        io_uring_prep_copy_file_range(sqe, src_fd, &src_offset, 
                                     dst_fd, &dst_offset, 
                                     chunk_size, 0);
        
        io_uring_sqe_set_data(sqe, (void*)chunk_size);
        
        if (io_uring_submit(&ring) < 0) {
            CHARON_LOG_WARN("charon", "io_uring submit failed");
            break;
        }
        
        struct io_uring_cqe* cqe;
        if (io_uring_wait_cqe(&ring, &cqe) < 0) {
            break;
        }
        
        ssize_t res = cqe->res;
        io_uring_cqe_seen(&ring, cqe);
        
        if (res < 0) {
            if (errno == EXDEV || errno == EINVAL || errno == ENOSYS) {
                CHARON_LOG_DEBUG("charon", "io_uring copy_file_range not supported");
                io_uring_queue_exit(&ring);
                return false;
            }
            CHARON_LOG_WARN("charon", "io_uring copy failed: %s", strerror(-res));
            break;
        }
        
        remaining -= res;
        ++charon_metrics.io_uring_ops;
        charon_metrics.copy_bytes_total += res;
    }
    
    io_uring_queue_exit(&ring);
    
    if (remaining == 0) {
        CHARON_LOG_DEBUG("charon", "io_uring copy completed successfully");
        return true;
    }
    
    return false;
}
#endif

static bool charon_copy_fd_fast(int src_fd, int dst_fd, uint64_t file_size, size_t chunk_kb) noexcept {
    (void)chunk_kb;
    if (file_size == 0) return true;
    
    auto cfg = charon_config.load();
    if (!cfg) return false;
    
    auto copy_start = std::chrono::steady_clock::now();
    
#ifdef HAS_IO_URING
    if (cfg->enable_io_uring) {
        if (charon_copy_fd_io_uring(src_fd, dst_fd, file_size)) {
            auto copy_end = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                copy_end - copy_start);
            charon_metrics.copy_operations_time_ms += duration.count();
            CHARON_LOG_DEBUG("charon", "io_uring copy completed: %lu bytes in %ld ms", 
                     file_size, duration.count());
            return true;
        }
        CHARON_LOG_DEBUG("charon", "io_uring failed, falling back");
    }
#endif
    
    charon_ensure_adaptive_copy_buffer(file_size);
    
    if (cfg->use_copy_file_range) {
#if PLATFORM_LINUX
        off_t offset = 0;
        uint64_t total_copied = 0;
        
        while (offset < static_cast<off_t>(file_size)) {
            size_t to_copy = file_size - offset;
            if (to_copy > SSIZE_MAX) to_copy = SSIZE_MAX;
            
            ssize_t n = syscall(SYS_copy_file_range, 
                                src_fd, &offset, 
                                dst_fd, nullptr,
                                to_copy, 0);
            
            if (n > 0) { 
                total_copied += n;
                ++charon_metrics.copy_file_range_calls;
                charon_metrics.copy_bytes_total += n;
                
                if (offset >= static_cast<off_t>(file_size)) {
                    auto copy_end = std::chrono::steady_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                        copy_end - copy_start);
                    charon_metrics.copy_operations_time_ms += duration.count();
                    
                    charon_secure_clear_buffer();
                    
                    CHARON_LOG_DEBUG("charon", "copy_file_range completed: %lu bytes in %ld ms", 
                             total_copied, duration.count());
                    return true;
                }
                continue; 
            }
            
            if (n == 0 || errno == EXDEV || errno == EINVAL || errno == ENOSYS) {
                CHARON_LOG_DEBUG("charon", "copy_file_range not supported, falling back: %s", strerror(errno));
                break;
            }
            
            if (errno == EINTR) continue;
            
            CHARON_LOG_WARN("charon", "copy_file_range failed: %s", strerror(errno));
            break;
        }
        
#elif PLATFORM_FREEBSD && __FreeBSD__ >= 13
        off_t offset = 0;
        uint64_t total_copied = 0;
        
        while (offset < static_cast<off_t>(file_size)) {
            size_t to_copy = file_size - offset;
            if (to_copy > SSIZE_MAX) to_copy = SSIZE_MAX;
            
            ssize_t n = copy_file_range(src_fd, &offset, 
                                       dst_fd, nullptr,
                                       to_copy, 0);
            
            if (n > 0) { 
                offset += n;
                total_copied += n;
                ++charon_metrics.copy_file_range_calls;
                charon_metrics.copy_bytes_total += n;
                
                if (offset >= static_cast<off_t>(file_size)) {
                    auto copy_end = std::chrono::steady_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                        copy_end - copy_start);
                    charon_metrics.copy_operations_time_ms += duration.count();
                    
                    charon_secure_clear_buffer();
                    
                    CHARON_LOG_DEBUG("charon", "copy_file_range completed: %lu bytes in %ld ms", 
                             total_copied, duration.count());
                    return true;
                }
                continue; 
            }
            
            if (n == 0 || errno == EXDEV || errno == EINVAL || errno == ENOSYS) {
                CHARON_LOG_DEBUG("charon", "copy_file_range not supported, falling back: %s", strerror(errno));
                break;
            }
            
            if (errno == EINTR) continue;
            
            CHARON_LOG_WARN("charon", "copy_file_range failed: %s", strerror(errno));
            break;
        }
#endif
    }
    
    CHARON_LOG_DEBUG("charon", "Using fallback copy for %lu bytes", file_size);
    ++charon_metrics.fallback_copy_calls;
    
    uint64_t remaining = file_size;
    size_t chunks = 0;
    int yield_every = cfg->yield_every_chunks;
    
    if (lseek(src_fd, 0, SEEK_SET) == static_cast<off_t>(-1) ||
        lseek(dst_fd, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        CHARON_LOG_ERROR("charon", "lseek failed in fallback copy: %s", strerror(errno));
        charon_secure_clear_buffer();
        return false;
    }
    
    while (remaining > 0) {
        size_t toread = std::min(g_copy_buffer.size(), static_cast<size_t>(remaining));
        ssize_t r = charon_safe_read(src_fd, g_copy_buffer.data(), toread);
        
        if (r < 0) {
            CHARON_LOG_ERROR("charon", "read failed during fallback copy: %s", strerror(errno));
            charon_secure_clear_buffer();
            return false;
        } else if (r == 0) {
            CHARON_LOG_ERROR("charon", "Unexpected EOF during fallback copy: expected %lu, got %lu bytes",
                     static_cast<unsigned long>(file_size),
                     static_cast<unsigned long>(file_size - remaining));
            charon_secure_clear_buffer();
            return false;
        }
        
        ssize_t w = charon_safe_write(dst_fd, g_copy_buffer.data(), r);
        if (w != r) {
            CHARON_LOG_ERROR("charon", "write failed during fallback copy: wrote %ld/%ld bytes: %s",
                     w, r, strerror(errno));
            charon_secure_clear_buffer();
            return false;
        }
        
        remaining -= r;
        charon_metrics.copy_bytes_total += r;
        
        if (++chunks % yield_every == 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(50));
        }
    }
    
    charon_secure_clear_buffer();
    
    auto copy_end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        copy_end - copy_start);
    charon_metrics.copy_operations_time_ms += duration.count();
    
    CHARON_LOG_DEBUG("charon", "Fallback copy completed: %lu bytes in %ld ms", 
              file_size, duration.count());
    return true;
}

// -----------------------------------------------------------------------------
// Charon Vessel — Disk space checks
// -----------------------------------------------------------------------------
static bool charon_check_destination_space(const std::string& parent_dir,
                                    uint64_t file_size,
                                    const Config& cfg,
                                    bool final_check = false) noexcept {
    ++charon_metrics.integer_overflow_checks;
    
    if (file_size > std::numeric_limits<uint64_t>::max() - cfg.buffer_size_bytes()) {
        ++charon_metrics.errors;
        CHARON_LOG_ERROR("charon", "File size too large for safe calculation: %" PRIu64, file_size);
        return false;
    }
    
    uint64_t need = file_size + cfg.buffer_size_bytes();
    
    struct statvfs sv{};
    if (statvfs(parent_dir.c_str(), &sv) != 0) {
        CHARON_LOG_WARN("charon", "statvfs failed for %s: %s", parent_dir.c_str(), strerror(errno));
        return true;
    }
    
    uint64_t avail = static_cast<uint64_t>(sv.f_bavail) * sv.f_frsize;
    
    if (avail < need) {
        ++charon_metrics.out_of_space;
        charon_metrics.backpressure_events.fetch_add(1, std::memory_order_relaxed);
        
        if (final_check) {
            CHARON_LOG_ERROR("charon", "OUT OF SPACE on %s: need=%" PRIu64 " avail=%" PRIu64, 
                     parent_dir.c_str(), need, avail);
        } else {
            CHARON_LOG_WARN("charon", "low space on %s: need=%" PRIu64 " avail=%" PRIu64, 
                    parent_dir.c_str(), need, avail);
        }
        return false;
    }
    
    CHARON_LOG_DEBUG("charon", "Space check OK: %s (%lu avail, %lu needed)", 
              parent_dir.c_str(), avail, need);
    return true;
}

// -----------------------------------------------------------------------------
// Filesystem operations with conditional fsync
// -----------------------------------------------------------------------------
static int charon_fsync_dir_conditional(const char* path) noexcept {
    auto cfg_ptr = charon_config.load();
    if (!cfg_ptr) return 0;
    
    const Config& cfg = *cfg_ptr;
    
    if (cfg.minimize_fsync) {
        struct statfs fs_info{};
        if (statfs(path, &fs_info) == 0) {
            if (fs_info.f_type == 0xEF53 || // ext2/3/4
                fs_info.f_type == 0x58465342 || // XFS
                fs_info.f_type == 0x9123683E) { // btrfs
                CHARON_LOG_DEBUG("charon", "Skipping fsync for journaling FS at %s", path);
                return 0;
            }
        }
    }
    
    unique_fd fd(open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (!fd) {
        if (errno != ENOENT && errno != EACCES) {
            CHARON_LOG_WARN("charon", "open directory failed for fsync %s: %s", path, strerror(errno));
        }
        return -1;
    }
    
    if (fsync(fd.get()) != 0) {
        CHARON_LOG_WARN("charon", "fsync directory failed %s: %s", path, strerror(errno));
        ++charon_metrics.fsync_calls;
        return -1;
    }
    
    ++charon_metrics.fsync_calls;
    return 0;
}

// -----------------------------------------------------------------------------
// File identity for TOCTOU protection during copy operations
// -----------------------------------------------------------------------------
struct FileIdentity {
    dev_t device;
    ino_t inode;
    time_t mtime;
    off_t size;
    
    static FileIdentity from_stat(const struct stat& st) noexcept {
        return {st.st_dev, st.st_ino, st.st_mtime, st.st_size};
    }
    
    bool matches(const struct stat& st) const noexcept {
        return device == st.st_dev && 
               inode == st.st_ino && 
               mtime == st.st_mtime &&
               size == st.st_size;
    }
};

// -----------------------------------------------------------------------------
// Copy operation with metadata preservation — FIXED VERSION
// -----------------------------------------------------------------------------
static bool charon_copy_with_metadata(
        int src_fd,
        MemfdTempFile& tmp_file,
        const struct stat& st,
        const Config& cfg,
        const std::string& final_dst_path,
        unique_fd& out_dst_fd,
        FileIdentity& src_identity) noexcept
{
    CHARON_LOG_DEBUG("charon", "Starting copy with metadata preservation");

    out_dst_fd = unique_fd(dup(tmp_file.fd()));
    if (!out_dst_fd) {
        ++charon_metrics.errors;
        CHARON_LOG_ERROR("charon", "dup() of memfd failed: %s", strerror(errno));
        return false;
    }

    src_identity = FileIdentity::from_stat(st);

    // === CORRECT free space check ===
    size_t last_slash = final_dst_path.rfind('/');
    std::string dst_parent_dir;
    if (last_slash != std::string::npos) {
        dst_parent_dir = final_dst_path.substr(0, last_slash);
    } else {
        dst_parent_dir = ".";
    }

    if (!charon_check_destination_space(dst_parent_dir,
                                 static_cast<uint64_t>(st.st_size),
                                 cfg,
                                 true)) {
        CHARON_LOG_WARN("charon", "Insufficient space in destination directory: %s", dst_parent_dir.c_str());
        return false;
    }

    // === Data copying ===
    if (!charon_copy_fd_fast(src_fd,
                      out_dst_fd.get(),
                      static_cast<uint64_t>(st.st_size),
                      cfg.copy_chunk_kb)) {
        ++charon_metrics.errors;
        CHARON_LOG_ERROR("charon", "copy failed: %s", strerror(errno));
        return false;
    }

    // === fsync temporary file ===
    if (fsync(out_dst_fd.get()) != 0) {
        ++charon_metrics.errors;
        CHARON_LOG_ERROR("charon", "fsync of temporary memfd failed: %s", strerror(errno));
        return false;
    }

    // === Set current time (atime/mtime) ===
    struct timespec now{};
    if (clock_gettime(CLOCK_REALTIME, &now) == 0) {
        const struct timespec times[2] = { now, now };
        if (futimens(out_dst_fd.get(), times) != 0) {
            CHARON_LOG_WARN("charon", "futimens failed: %s", strerror(errno));
        }
    }

    // === Set permissions ===
    if (fchmod(out_dst_fd.get(), st.st_mode & 07777) != 0) {
        CHARON_LOG_WARN("charon", "fchmod failed: %s", strerror(errno));
    }

    // === Set owner (ignore EPERM) ===
    if (fchown(out_dst_fd.get(), st.st_uid, st.st_gid) != 0) {
        if (errno != EPERM && errno != EINVAL) {
            CHARON_LOG_WARN("charon", "fchown failed: %s", strerror(errno));
        }
    }

    CHARON_LOG_DEBUG("charon", "Copy with metadata completed successfully");
    return true;
}

// -----------------------------------------------------------------------------
// Charon Vessel — Security auditing and logging
// -----------------------------------------------------------------------------
class SecurityAudit {
    std::mutex mtx_;                          // Mutex for thread-safe access to in-memory log
    std::vector<std::string> audit_log_;      // In-memory ring buffer for recent audit entries
    std::atomic<bool> enabled_{true};         // Global enable/disable flag for auditing
    std::atomic<size_t> log_size_{0};         // Current number of entries (for quick size queries)
  
    // Writes a single entry to the persistent audit file
    void write_to_audit_file(const std::string& entry) noexcept {
        if (!enabled_.load(std::memory_order_relaxed)) return;
      
        unique_fd fd(open("/var/log/charon-audit.log",
                         O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0640));
        if (!fd) {
            CHARON_LOG_DEBUG("charon", "Failed to open audit log: %s", strerror(errno));
            return;
        }
      
        charon_safe_write(fd.get(), entry.data(), entry.size());
    }
  
public:
    // Singleton instance
    static SecurityAudit& instance() {
        static SecurityAudit audit;
        return audit;
    }
  
    // Logs a file operation with source, destination, success status and optional error
    void log_operation(const char* operation, const std::string& src,
                       const std::string& dst, bool success,
                       const char* error = nullptr) noexcept {
        if (!enabled_.load(std::memory_order_relaxed)) return;
      
        auto cfg_ptr = charon_config.load();
        if (!cfg_ptr || !cfg_ptr->enable_audit_log) return;
      
        // Generate timestamp
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        struct tm tm_time{};
        localtime_r(&t, &tm_time);
      
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_time);
      
        // Truncate long paths to prevent oversized entries
        auto truncate_path = [](const std::string& p) -> std::string {
            if (p.size() <= 256) return p;
            return p.substr(0, 253) + "...";
        };
      
        std::string safe_src = truncate_path(src);
        std::string safe_dst = truncate_path(dst);
      
        // Build audit entry (safe from buffer overflows)
        std::string entry = "[AUDIT][";
        entry += timestamp;
        entry += "][PID:";
        entry += std::to_string(getpid());
        entry += "] ";
        entry += operation;
        entry += ": ";
        entry += safe_src;
        entry += " -> ";
        entry += safe_dst;
        entry += " ";
        entry += success ? "SUCCESS" : "FAILED";
      
        if (error && error[0] != '\0') {
            entry += " (";
            // Sanitize error message: replace control chars and newlines
            for (const char* p = error; *p; ++p) {
                if (*p == '\n' || *p == '\r' || static_cast<unsigned char>(*p) < 32) {
                    entry += '?';
                } else {
                    entry += *p;
                }
            }
            entry += ")";
        }
      
        // Cap entry size to avoid potential DoS via extremely long paths/errors
        if (entry.size() > 4096) {
            entry.resize(4093);
            entry += "...";
        }
      
        entry += '\n';
      
        // Store in in-memory ring buffer
        try {
            std::lock_guard<std::mutex> lock(mtx_);
            audit_log_.emplace_back(entry.substr(0, entry.size() - 1)); // without final \n
            log_size_.fetch_add(1, std::memory_order_relaxed);
          
            if (audit_log_.size() > constants::MAX_AUDIT_LOG_SIZE) {
                audit_log_.erase(audit_log_.begin(),
                                 audit_log_.begin() + audit_log_.size() / 2);
                log_size_.store(audit_log_.size(), std::memory_order_relaxed);
            }
        } catch (...) {
            // Ignore allocation failures – audit must never crash the process
        }
      
        // Persist to file
        write_to_audit_file(entry);
    }
  
    // Enable or disable auditing globally
    void set_enabled(bool enabled) noexcept {
        enabled_.store(enabled, std::memory_order_relaxed);
    }
  
    // Current number of stored entries
    size_t size() const noexcept {
        return log_size_.load(std::memory_order_relaxed);
    }
  
    // Clear in-memory log
    void clear() noexcept {
        std::lock_guard<std::mutex> lock(mtx_);
        audit_log_.clear();
        log_size_.store(0, std::memory_order_relaxed);
    }
};

// -----------------------------------------------------------------------------
// Secure finalization of cross-device moves with TOCTOU protection
// -----------------------------------------------------------------------------
static bool charon_finalize_move_secure(const std::string& src_path,
                                const std::string& dst_path,
                                const std::string& parent_dir,
                                MemfdTempFile& tmp_file,
                                int src_fd,
                                const FileIdentity& src_identity) noexcept {
    CHARON_LOG_DEBUG("charon", "Finalizing move securely: %s -> %s", src_path.c_str(), dst_path.c_str());
    
    auto cfg_ptr = charon_config.load();
    if (!cfg_ptr) return false;
    const Config& cfg = *cfg_ptr;
    
    if (!charon_validate_destination_path(dst_path, cfg.archive_root)) {
        ++charon_metrics.security_errors;
        SecurityAudit::instance().log_operation("INVALID_PATH", src_path, dst_path, false, "Path traversal attempt");
        CHARON_LOG_ERROR("security", "Invalid destination path (possible traversal): %s", dst_path.c_str());
        return false;
    }
    
    struct stat current_st;
    if (fstat(src_fd, &current_st) != 0) {
        ++charon_metrics.security_errors;
        SecurityAudit::instance().log_operation("FSTAT_FAILED", src_path, dst_path, false, strerror(errno));
        CHARON_LOG_ERROR("security", "Cannot verify source file identity: fstat failed");
        return false;
    }
    
    if (!src_identity.matches(current_st)) {
        ++charon_metrics.security_errors;
        SecurityAudit::instance().log_operation("IDENTITY_MISMATCH", src_path, dst_path, false, "File changed during operation");
        CHARON_LOG_ERROR("security", "Source file changed during operation (TOCTOU detected)");
        return false;
    }
    
    // Create final destination file from memfd
    unique_fd dst_fd(open(dst_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644));
    if (!dst_fd) {
        ++charon_metrics.errors;
        SecurityAudit::instance().log_operation("CREATE_FAILED", src_path, dst_path, false, strerror(errno));
        CHARON_LOG_ERROR("charon", "create dst failed %s : %s", dst_path.c_str(), strerror(errno));
        return false;
    }
    
    // Copy from memfd to final destination
    lseek(tmp_file.fd(), 0, SEEK_SET);
    struct stat tmp_st;
    if (fstat(tmp_file.fd(), &tmp_st) != 0) {
        CHARON_LOG_ERROR("charon", "fstat memfd failed: %s", strerror(errno));
        return false;
    }
    
    if (!charon_copy_fd_fast(tmp_file.fd(), dst_fd.get(), tmp_st.st_size, cfg.copy_chunk_kb)) {
        CHARON_LOG_ERROR("charon", "copy from memfd failed");
        unlink(dst_path.c_str());
        return false;
    }
    
    if (fsync(dst_fd.get()) != 0) {
        CHARON_LOG_WARN("charon", "fsync destination failed: %s", strerror(errno));
    }
    
    dst_fd.reset();
    
    if (charon_fsync_dir_conditional(parent_dir.c_str()) != 0) {
        CHARON_LOG_WARN("charon", "fsync_dir post-create failed %s", parent_dir.c_str());
    }
    
    int unlink_retries = 3;
    bool src_removed = false;
    
    while (unlink_retries-- > 0 && !src_removed) {
        struct stat verify_st_before, verify_st_after;
        
        if (fstat(src_fd, &verify_st_before) == 0 && src_identity.matches(verify_st_before)) {
            unique_fd verify_fd(open(src_path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
            if (verify_fd && fstat(verify_fd.get(), &verify_st_after) == 0) {
                if (verify_st_before.st_ino == verify_st_after.st_ino &&
                    verify_st_before.st_dev == verify_st_after.st_dev) {
                    
                    if (unlink(src_path.c_str()) == 0) {
                        src_removed = true;
                        ++charon_metrics.cross_device_moves;
                        SecurityAudit::instance().log_operation("CROSS_DEVICE_MOVE", src_path, dst_path, true);
                        
                        auto name_pos = src_path.rfind('/');
                        if (name_pos != std::string::npos) {
                            std::string src_parent = src_path.substr(0, name_pos);
                            if (charon_fsync_dir_conditional(src_parent.c_str()) != 0) {
                                CHARON_LOG_WARN("charon", "fsync_dir (src_parent) failed %s", src_parent.c_str());
                            }
                        }
                        
                        CHARON_LOG_DEBUG("charon", "Secure cross-device move completed successfully");
                        break;
                    } else {
                        int e = errno;
                        if (e == EINTR) {
                            continue;
                        } else if (e == EBUSY || e == EPERM) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            continue;
                        }
                    }
                }
            }
        } else {
            ++charon_metrics.security_errors;
            SecurityAudit::instance().log_operation("VALIDATION_FAILED", src_path, dst_path, false, "Source file changed during unlink");
            CHARON_LOG_WARN("security", "Source file validation failed during unlink attempt");
            break;
        }
    }
    
    if (!src_removed) {
        ++charon_metrics.errors;
        SecurityAudit::instance().log_operation("SRC_REMOVE_FAILED", src_path, dst_path, false, "Could not remove source");
        CHARON_LOG_ERROR("charon", "CRITICAL: Failed to remove source after cross-device move: %s", 
                 src_path.c_str());
        
        struct stat dst_st;
        if (stat(dst_path.c_str(), &dst_st) == 0) {
            if (charon_validate_destination_path(dst_path, cfg.archive_root)) {
                CHARON_LOG_WARN("charon", "Attempting secure rollback for: %s", dst_path.c_str());
                if (unlink(dst_path.c_str()) != 0) {
                    SecurityAudit::instance().log_operation("ROLLBACK_FAILED", src_path, dst_path, false, strerror(errno));
                    CHARON_LOG_ERROR("charon", "Rollback failed - could not remove destination: %s", 
                             dst_path.c_str());
                } else {
                    SecurityAudit::instance().log_operation("ROLLBACK_SUCCESS", src_path, dst_path, true, "Destination removed");
                    CHARON_LOG_WARN("charon", "Rollback successful: removed destination file");
                }
            } else {
                SecurityAudit::instance().log_operation("SECURITY_ALERT", src_path, dst_path, false, "Destination path validation failed");
                CHARON_LOG_ERROR("security", "Security alert: destination path validation failed, skipping rollback");
            }
        }
        
        if (charon_fsync_dir_conditional(parent_dir.c_str()) != 0) {
            CHARON_LOG_WARN("charon", "fsync_dir after rollback failed %s", parent_dir.c_str());
        }
        
        return false;
    }
    
    return true;
}

// -----------------------------------------------------------------------------
// Charon Vessel — Secure cross-device file moves
// -----------------------------------------------------------------------------
static bool charon_cross_device_move(const std::string& src, 
                                     const std::string& dst) noexcept {
    CHARON_LOG_DEBUG("charon", "Starting secure cross-device move: %s -> %s", src.c_str(), dst.c_str());
    
    auto cfg_ptr = charon_config.load();
    if (!cfg_ptr) {
        ++charon_metrics.errors;
        CHARON_LOG_ERROR("charon", "no config in charon_cross_device_move");
        return false;
    }
    
    const Config& cfg = *cfg_ptr;
    
    if (!charon_validate_destination_path(dst, cfg.archive_root)) {
        ++charon_metrics.security_errors;
        CHARON_LOG_ERROR("security", "Invalid destination path: %s", dst.c_str());
        return false;
    }
    
    unique_fd src_fd;
    struct stat st{};
    if (!charon_validate_source_file(src, src_fd, st)) {
        return false;
    }
    
    auto parent_pos = dst.rfind('/');
    if (parent_pos == std::string::npos) {
        ++charon_metrics.errors;
        CHARON_LOG_ERROR("charon", "Invalid destination path: %s", dst.c_str());
        return false;
    }
    
    std::string parent_dir = dst.substr(0, parent_pos);
    
    if (!charon_check_destination_space(parent_dir, 
                                 static_cast<uint64_t>(st.st_size), 
                                 cfg)) {
        return false;
    }
    
    MemfdTempFile tmp_file("charon_copy");
    if (!tmp_file.valid()) {
        ++charon_metrics.errors;
        CHARON_LOG_ERROR("charon", "memfd temp file creation failed");
        return false;
    }
    
    unique_fd dst_fd;
    FileIdentity src_identity;
    if (!charon_copy_with_metadata(src_fd.get(),
                            tmp_file,
                            st,
                            cfg,
                            dst,                    
                            dst_fd,
                            src_identity)) {
        return false;
    }
    dst_fd.reset(-1);
    
    if (!charon_finalize_move_secure(src, dst, parent_dir, tmp_file, src_fd.get(), src_identity)) {
        return false;
    }
    
    CHARON_LOG_DEBUG("charon", "Secure cross-device move completed: %s -> %s", src.c_str(), dst.c_str());
    return true;
}

// -----------------------------------------------------------------------------
// CopyTask - RingBuffer
// -----------------------------------------------------------------------------
struct CopyTask {
    std::string src;
    std::string dst;
    std::promise<bool> result;
    bool is_exit = false;
   
    CopyTask(std::string s, std::string d)
        : src(std::move(s)), dst(std::move(d)) {}
   
    CopyTask() : src(""), dst(""), is_exit(false) {}
};

// -----------------------------------------------------------------------------
// Charon Vessel — Parallel copy task management
// -----------------------------------------------------------------------------

// Lock-free ring buffer for efficient task queueing
template<typename T, size_t N>
class RingBuffer {
    static_assert(N > 0 && (N & (N - 1)) == 0, "N must be power of two");
   
    alignas(64) std::atomic<size_t> head_{0};
    alignas(64) std::atomic<size_t> tail_{0};
    std::array<std::optional<T>, N> buffer_;
   
public:
    RingBuffer() = default;
   
    ~RingBuffer() = default;
   
    RingBuffer(const RingBuffer&) = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;
   
    RingBuffer(RingBuffer&&) = delete;
    RingBuffer& operator=(RingBuffer&&) = delete;
   
    bool try_push(T&& item) noexcept {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t tail = tail_.load(std::memory_order_acquire);
       
        if ((head - tail) >= N) return false;
       
        buffer_[head & (N - 1)].emplace(std::move(item));
        head_.store(head + 1, std::memory_order_release);
        return true;
    }
   
    bool try_pop(T& item) noexcept {
        size_t tail = tail_.load(std::memory_order_relaxed);
        size_t head = head_.load(std::memory_order_acquire);
       
        if (head == tail) return false;
       
        auto& opt = buffer_[tail & (N - 1)];
        if (!opt) return false;
       
        item = std::move(*opt);
        opt.reset();
       
        tail_.store(tail + 1, std::memory_order_release);
        return true;
    }
   
    size_t size() const noexcept {
        return head_.load(std::memory_order_acquire) -
               tail_.load(std::memory_order_acquire);
    }
   
    bool empty() const noexcept {
        return size() == 0;
    }
   
    bool full() const noexcept {
        return size() >= N;
    }
};


class CharonWorkerPool {
    std::vector<std::thread> workers_;
    std::unique_ptr<RingBuffer<CopyTask, constants::RING_BUFFER_SIZE>> ring_buffer_;
    mutable std::mutex workers_mtx_;
    std::condition_variable cv_;
    std::atomic<bool> stop_{false};
    std::atomic<int> target_threads_{8};
    std::atomic<int> active_threads_{0};
    std::atomic<int> pending_exits_{0};
    std::atomic<int> exit_ack_{0};

    void worker() noexcept {
        CHARON_LOG_DEBUG("charon", "Copy worker thread started");
        charon_block_signals_in_worker_threads();
       
        while (!stop_.load(std::memory_order_acquire)) {
            if (charon_shutdown.load(std::memory_order_acquire)) {
                CHARON_LOG_DEBUG("charon", "Global shutdown detected, worker exiting");
                return;
            }
           
            CopyTask task;
            bool got_task = false;
           
            for (int i = 0; i < 10 && !got_task; ++i) {
                if (ring_buffer_->try_pop(task)) {
                    got_task = true;
                    charon_metrics.queued_tasks.fetch_sub(1, std::memory_order_relaxed);
                    break;
                }
               
                if (stop_.load(std::memory_order_acquire) || charon_shutdown.load(std::memory_order_acquire)) {
                    return;
                }
               
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
           
            if (!got_task) {
                std::unique_lock<std::mutex> lk(workers_mtx_);
                cv_.wait(lk, [&] {
                    return stop_.load(std::memory_order_acquire) ||
                           !ring_buffer_->empty() ||
                           charon_shutdown.load(std::memory_order_acquire);
                });
               
                if (stop_.load(std::memory_order_acquire) || charon_shutdown.load(std::memory_order_acquire)) {
                    CHARON_LOG_DEBUG("charon", "Copy worker thread stopping");
                    return;
                }
                if (ring_buffer_->empty()) continue;
               
                if (!ring_buffer_->try_pop(task)) continue;
                charon_metrics.queued_tasks.fetch_sub(1, std::memory_order_relaxed);
            }
           
            if (task.is_exit) {
                exit_ack_.fetch_add(1, std::memory_order_release);
                try { task.result.set_value(false); } catch(...) {}
                CHARON_LOG_DEBUG("charon", "Copy worker thread exiting by request");
                return;
            }
           
            ++charon_metrics.active_copies;
            active_threads_.fetch_add(1, std::memory_order_relaxed);
           
            CHARON_LOG_DEBUG("charon", "Processing copy task: %s -> %s",
                     task.src.c_str(), task.dst.c_str());
           
            bool success = charon_cross_device_move(task.src, task.dst);
           
            try {
                task.result.set_value(success);
            } catch (...) {
                CHARON_LOG_WARN("charon", "Failed to set task result");
            }
           
            active_threads_.fetch_sub(1, std::memory_order_relaxed);
            --charon_metrics.active_copies;
           
            CHARON_LOG_DEBUG("charon", "Copy task completed: %s", success ? "success" : "failed");
        }
    }

    void wait_for_exits(int count) noexcept {
        auto start = std::chrono::steady_clock::now();
        auto timeout = std::chrono::seconds(5);
       
        while (exit_ack_.load(std::memory_order_acquire) < count) {
            if (std::chrono::steady_clock::now() - start > timeout) {
                CHARON_LOG_WARN("charon", "Timeout waiting for %d threads to exit", count);
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
       
        int acked = exit_ack_.exchange(0, std::memory_order_relaxed);
        pending_exits_.fetch_sub(acked, std::memory_order_relaxed);
    }

public:
    explicit CharonWorkerPool(int threads) {
        target_threads_.store(threads, std::memory_order_relaxed);
       
        ring_buffer_ = std::make_unique<RingBuffer<CopyTask, constants::RING_BUFFER_SIZE>>();
       
        std::lock_guard<std::mutex> lk(workers_mtx_);
        for (int i = 0; i < threads; ++i) {
            workers_.emplace_back(&CharonWorkerPool::worker, this);
        }
       
        CHARON_LOG_INFO("charon", "Charon worker pool created with %d threads (lock-free ring buffer)", threads);
    }
   
    ~CharonWorkerPool() {
        stop();
    }

    void force_notify() noexcept {
        cv_.notify_all();
    }

    void stop() noexcept {
        CHARON_LOG_INFO("charon", "Stopping charon worker pool");
        stop_.store(true, std::memory_order_release);
        cv_.notify_all();
       
        std::lock_guard<std::mutex> lk(workers_mtx_);
        for (auto& t : workers_) {
            if (t.joinable()) t.join();
        }
       
        workers_.clear();
        CHARON_LOG_INFO("charon", "Charon worker pool stopped");
    }
   
    std::future<bool> enqueue(CopyTask task) {
        std::future<bool> fut = task.result.get_future();
       
        if (stop_.load(std::memory_order_acquire) || charon_shutdown.load(std::memory_order_acquire)) {
            try {
                task.result.set_value(false);
            } catch(...) {}
            return fut;
        }
       
        if (ring_buffer_->full()) {
            static std::mutex fallback_mtx;
            static std::deque<CopyTask> fallback_queue;
           
            std::lock_guard<std::mutex> lk(fallback_mtx);
            if (fallback_queue.size() >= constants::MAX_FALLBACK_QUEUE) {
                ++charon_metrics.queue_full_rejections;
                CHARON_LOG_WARN("charon", "Copy queue full (%zu ring + %zu fallback items), rejecting task",
                         ring_buffer_->size(), fallback_queue.size());
                try {
                    task.result.set_value(false);
                } catch(...) {}
                return fut;
            }
           
            fallback_queue.push_back(std::move(task));
            charon_metrics.queued_tasks.fetch_add(1, std::memory_order_relaxed);
           
            for (size_t i = 0; i < 10 && !fallback_queue.empty(); ++i) {
                if (ring_buffer_->try_push(std::move(fallback_queue.front()))) {
                    fallback_queue.pop_front();
                    cv_.notify_one();
                } else {
                    break;
                }
            }
           
            return fut;
        }
       
        if (ring_buffer_->try_push(std::move(task))) {
            charon_metrics.queued_tasks.fetch_add(1, std::memory_order_relaxed);
            cv_.notify_one();
            return fut;
        }
       
        return fut;
    }
   
    void adjust_threads(int new_target) noexcept {
        int cur = target_threads_.load(std::memory_order_relaxed);
       
        if (new_target < constants::MIN_COPY_THREADS) {
            new_target = constants::MIN_COPY_THREADS;
        }
        if (new_target > constants::MAX_COPY_THREADS) {
            new_target = constants::MAX_COPY_THREADS;
        }
       
        if (new_target == cur) return;
       
        CHARON_LOG_INFO("charon", "Adjusting copy threads from %d to %d", cur, new_target);
        target_threads_.store(new_target, std::memory_order_relaxed);
        charon_metrics.current_copy_threads.store(new_target, std::memory_order_relaxed);
       
        std::lock_guard<std::mutex> lk(workers_mtx_);
        int current_workers = static_cast<int>(workers_.size());
       
        if (new_target > current_workers) {
            int to_add = new_target - current_workers;
            for (int i = 0; i < to_add; ++i) {
                workers_.emplace_back(&CharonWorkerPool::worker, this);
            }
           
            CHARON_LOG_INFO("charon", "Added %d copy threads, now at %d", to_add, new_target);
        } else if (new_target < current_workers) {
            int to_exit = current_workers - new_target;
            CHARON_LOG_INFO("charon", "Scheduling %d threads to exit", to_exit);
           
            pending_exits_.fetch_add(to_exit, std::memory_order_relaxed);
           
            for (int i = 0; i < to_exit; ++i) {
                CopyTask exit_task;
                exit_task.is_exit = true;
               
                int attempts = 0;
                while (attempts < 10 && !ring_buffer_->try_push(std::move(exit_task))) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    ++attempts;
                }
               
                if (attempts == 10) {
                    static std::mutex exit_mtx;
                    static std::deque<CopyTask> exit_queue;
                    std::lock_guard<std::mutex> lk(exit_mtx);
                    exit_queue.push_back(std::move(exit_task));
                }
               
                charon_metrics.queued_tasks.fetch_add(1, std::memory_order_relaxed);
            }
           
            cv_.notify_all();
           
            wait_for_exits(to_exit);
           
            for (auto it = workers_.begin(); it != workers_.end(); ) {
                if (!it->joinable()) {
                    it = workers_.erase(it);
                } else {
                    ++it;
                }
            }
           
            CHARON_LOG_INFO("charon", "Thread adjustment completed: %d -> %d", cur, new_target);
        }
    }
   
    int current_target() const noexcept {
        return target_threads_.load(std::memory_order_relaxed);
    }
   
    size_t queue_size() const noexcept {
        return ring_buffer_ ? ring_buffer_->size() : 0;
    }
};
static std::shared_ptr<CharonWorkerPool> g_charon_pool;

// -----------------------------------------------------------------------------
// Charon Vessel — Adaptive resource throttling
// -----------------------------------------------------------------------------
static void charon_throttle_adaptive(bool low_space, const Config& cfg) noexcept {
    auto pool = g_charon_pool;
    if (!pool || !cfg.adaptive_throttle) return;
    
    int cur = pool->current_target();
    int new_target = cur;
    
    if (low_space && cur > constants::MIN_COPY_THREADS) {
        new_target = std::max(constants::MIN_COPY_THREADS, cur / 2);
        CHARON_LOG_INFO("charon", "Low space detected, reducing copy threads to %d", new_target);
    } else if (!low_space && cur < cfg.copy_threads) {
        new_target = std::min(cfg.copy_threads, cur * 2);
        
        size_t queue_size = pool->queue_size();
        if (queue_size == 0) {
            new_target = std::min(cfg.copy_threads, cur + 1);
        } else if (queue_size > 100) {
            new_target = std::min(cfg.copy_threads, cur * 3);
        }
        
        if (new_target > cur) {
            CHARON_LOG_INFO("charon", "Space available, increasing copy threads to %d (queue: %zu)", 
                    new_target, queue_size);
        }
    }
    
    if (new_target != cur) {
        pool->adjust_threads(new_target);
    }
}

// -----------------------------------------------------------------------------
// Charon Vessel — Main rename operation with cross-device fallback
// -----------------------------------------------------------------------------
static bool charon_atomic_rename(const std::string& src, const std::string& dst) noexcept {
    CHARON_LOG_DEBUG("charon", "Attempting rename: %s -> %s", src.c_str(), dst.c_str());

    auto cfg_ptr = charon_config.load();
    if (!cfg_ptr) {
        ++charon_metrics.errors;
        CHARON_LOG_ERROR("charon", "no config in charon_atomic_rename");
        return false;
    }

    const Config& cfg = *cfg_ptr;

    if (!charon_validate_destination_path(dst, cfg.archive_root)) {
        ++charon_metrics.security_errors;
        CHARON_LOG_ERROR("security", "Invalid destination path in charon_atomic_rename: %s", dst.c_str());
        return false;
    }

    // === SIMPLE AND RELIABLE: create directories from charon ===
    size_t last_slash = dst.find_last_of('/');
    if (last_slash != std::string::npos) {
        std::string dest_dir = dst.substr(0, last_slash);

        if (charon_mkdir_p_safe(dest_dir) != 0) {
            CHARON_LOG_ERROR("charon", "Failed to create destination directory: %s (%s)",
                         dest_dir.c_str(), strerror(errno));
            return false;
        }

        charon_fsync_dir_conditional(dest_dir.c_str());
    }

    // === Rest of the code unchanged ===
    if (charon_atomic_file_replace(dst, src)) {
        charon_metrics.atomic_rename_success.fetch_add(1);
        g_rotation_failures.store(0, std::memory_order_relaxed);
        ++charon_metrics.rotated_total;
        SecurityAudit::instance().log_operation("ATOMIC_RENAME", src, dst, true);
        CHARON_LOG_DEBUG("charon", "Atomic rename successful: %s -> %s", src.c_str(), dst.c_str());
        return true;
    } else {
        charon_metrics.atomic_rename_failed.fetch_add(1);
    }

    if (rename(src.c_str(), dst.c_str()) == 0) {
        g_rotation_failures.store(0, std::memory_order_relaxed);
        ++charon_metrics.rotated_total;
        SecurityAudit::instance().log_operation("DIRECT_RENAME", src, dst, true);
        CHARON_LOG_DEBUG("charon", "Direct rename successful: %s -> %s", src.c_str(), dst.c_str());
        return true;
    }

    if (errno != EXDEV) {
        ++charon_metrics.errors;
        g_rotation_failures.fetch_add(1, std::memory_order_relaxed);

        if (errno == ENOSPC) {
            SecurityAudit::instance().log_operation("RENAME_NO_SPACE", src, dst, false, strerror(errno));
            CHARON_LOG_ERROR("charon", "rename failed due to NO SPACE: %s -> %s", src.c_str(), dst.c_str());
            charon_metrics.out_of_space.fetch_add(1, std::memory_order_relaxed);
        } else {
            SecurityAudit::instance().log_operation("RENAME_FAILED", src, dst, false, strerror(errno));
            CHARON_LOG_WARN("charon", "rename failed (not EXDEV): %s -> %s : %s",
                        src.c_str(), dst.c_str(), strerror(errno));
        }

        return false;
    }

    CHARON_LOG_DEBUG("charon", "EXDEV detected, using cross-device copy: %s -> %s", src.c_str(), dst.c_str());

    auto pool = g_charon_pool;
    if (!pool) {
        ++charon_metrics.errors;
        CHARON_LOG_ERROR("charon", "charon pool not initialized");
        return false;
    }

    CopyTask task{src, dst};
    auto fut = pool->enqueue(std::move(task));
    bool ok = fut.get();

    if (ok) {
        g_rotation_failures.store(0, std::memory_order_relaxed);
        ++charon_metrics.rotated_total;
        SecurityAudit::instance().log_operation("CROSS_DEVICE_SUCCESS", src, dst, true);
        CHARON_LOG_DEBUG("charon", "Cross-device rename successful: %s -> %s", src.c_str(), dst.c_str());
    } else {
        g_rotation_failures.fetch_add(1, std::memory_order_relaxed);
        SecurityAudit::instance().log_operation("CROSS_DEVICE_FAILED", src, dst, false, "Copy failed");
        CHARON_LOG_WARN("charon", "Cross-device rename failed: %s -> %s", src.c_str(), dst.c_str());
    }

    return ok;
}

// -----------------------------------------------------------------------------
// Directory scanning with xattr-based optimization
// -----------------------------------------------------------------------------
static std::vector<std::pair<time_t, std::string>> charon_scan_fresh(const std::string& path) noexcept {
    auto cfg_ptr = charon_config.load();
    if (!cfg_ptr) return {};
    
    const Config& cfg = *cfg_ptr;
    
    if (cfg.enable_fast_scan) {
        return charon_scan_fresh_efficient(path);
    }
    
    CHARON_LOG_DEBUG("charon", "Scanning directory: %s", path.c_str());
    std::vector<std::pair<time_t, std::string>> files;
    
    std::unique_ptr<DIR, int(*)(DIR*)> dir(opendir(path.c_str()), closedir);
    if (!dir) {
        CHARON_LOG_ERROR("charon", "Failed to open directory: %s : %s", path.c_str(), strerror(errno));
        return files;
    }
    
    files.reserve(1000);
    
    struct dirent* de;
    while ((de = readdir(dir.get())) != nullptr) {
        if (de->d_name[0] == '.') continue;
        
        std::string full = path + "/" + de->d_name;
        
        if (charon_contains_path_traversal(full) || !charon_validate_path_length(full)) {
            ++charon_metrics.invalid_paths_rejected;
            CHARON_LOG_WARN("security", "Skipping file with invalid path: %s", full.c_str());
            continue;
        }
        
        struct stat st{};
        
        if (lstat(full.c_str(), &st) != 0) {
            CHARON_LOG_WARN("charon", "lstat failed for %s: %s", full.c_str(), strerror(errno));
            continue;
        }
        
        if (!S_ISREG(st.st_mode)) continue;
        
        files.emplace_back(st.st_mtime, full);
    }
    
    CHARON_LOG_DEBUG("charon", "Scanned %zu files from %s", files.size(), path.c_str());
    return files;
}

// -----------------------------------------------------------------------------
// Directory cleanup and reclamation
// -----------------------------------------------------------------------------
class CharonDirectoryCleanup {
    std::unordered_set<std::string> pending_;
    std::unordered_set<std::string> active_dirs_;
    mutable std::mutex mtx_;
    std::atomic<time_t> last_sweep_{0};
    std::atomic<int> sweep_count_{0};
    
public:
    void mark_active(const std::string& dir) {
        std::lock_guard<std::mutex> lk(mtx_);
        active_dirs_.insert(dir);
        pending_.erase(dir);
    }
    
    void release_active(const std::string& dir) {
        std::lock_guard<std::mutex> lk(mtx_);
        active_dirs_.erase(dir);
        
        time_t now = time(nullptr);
        if (sweep_count_.load() < 100 || now - last_sweep_.load() > 60) {
            pending_.insert(dir);
            CHARON_LOG_DEBUG("charon", "Marked directory for deletion: %s", dir.c_str());
        }
    }
    
    void mark(const std::string& path) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (active_dirs_.find(path) == active_dirs_.end()) {
            if (pending_.size() < 1000) {
                pending_.insert(path);
                CHARON_LOG_DEBUG("charon", "Marked directory for deletion: %s", path.c_str());
            } else {
                CHARON_LOG_WARN("charon", "Too many pending deletions, skipping: %s", path.c_str());
            }
        }
    }
    
    void sweep() {
        time_t now = time(nullptr);
        if (now - last_sweep_.load() < 10) {
            return;
        }
        
        std::vector<std::string> batch;
        
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (pending_.empty()) {
                last_sweep_.store(now, std::memory_order_relaxed);
                return;
            }
            
            size_t batch_size = std::min(pending_.size(), static_cast<size_t>(100));
            auto it = pending_.begin();
            for (size_t i = 0; i < batch_size && it != pending_.end(); ++i, ++it) {
                batch.push_back(*it);
            }
            
            for (const auto& dir : batch) {
                pending_.erase(dir);
            }
        }
        
        CHARON_LOG_DEBUG("charon", "Sweeping %zu marked directories", batch.size());
        
        for (const auto& dir : batch) {
            struct stat st{};
            if (stat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
                continue;
            }
            
            if (rmdir(dir.c_str()) == 0) {
                ++charon_metrics.cleanup_dirs;
                CHARON_LOG_DEBUG("charon", "Removed empty directory: %s", dir.c_str());
            } else if (errno == ENOTEMPTY || errno == EBUSY) {
                mark(dir);
                CHARON_LOG_DEBUG("charon", "Directory not empty/busy, will retry: %s", dir.c_str());
            } else if (errno != EINTR) {
                CHARON_LOG_WARN("charon", "rmdir failed %s : %s", dir.c_str(), strerror(errno));
            }
        }
        
        last_sweep_.store(now, std::memory_order_relaxed);
        sweep_count_.fetch_add(1, std::memory_order_relaxed);
    }
};

// -----------------------------------------------------------------------------
// Date parsing utilities for archive path validation
// -----------------------------------------------------------------------------
namespace date_utils {
    static bool is_leap_year(int year) noexcept {
        return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    }
    
    static int days_in_month(int year, int month) noexcept {
        static const int month_days[] = {31, 28, 31, 30, 31, 30, 
                                        31, 31, 30, 31, 30, 31};
        
        if (month < 1 || month > 12) return 0;
        
        int days = month_days[month - 1];
        if (month == 2 && is_leap_year(year)) {
            days = 29;
        }
        
        return days;
    }
}

static bool charon_parse_date_from_path(const std::string& path,
                                 const std::string& archive_root,
                                 int& year, int& month, int& day) noexcept {
    if (path.size() <= archive_root.size() || 
        path.compare(0, archive_root.size(), archive_root) != 0) {
        return false;
    }
    
    const char* p = path.c_str() + archive_root.size();
    if (*p == '/') ++p;
    
    char year_str[5], month_str[3], day_str[3];
    year_str[0] = month_str[0] = day_str[0] = '\0';
    
    if (sscanf(p, "%4[0-9]/%2[0-9]/%2[0-9]", year_str, month_str, day_str) != 3) {
        return false;
    }
    
    for (int i = 0; year_str[i]; ++i) if (!isdigit(year_str[i])) return false;
    for (int i = 0; month_str[i]; ++i) if (!isdigit(month_str[i])) return false;
    for (int i = 0; day_str[i]; ++i) if (!isdigit(day_str[i])) return false;
    
    year = atoi(year_str);
    month = atoi(month_str);
    day = atoi(day_str);
    
    if (year < 2000 || year > 2099) return false;
    if (month < 1 || month > 12) return false;
    
    int max_days = date_utils::days_in_month(year, month);
    if (day < 1 || day > max_days) return false;
    
    CHARON_LOG_DEBUG("charon", "Parsed date from path: %04d-%02d-%02d from %s", 
              year, month, day, path.c_str());
    return true;
}

// -----------------------------------------------------------------------------
// Comprehensive cleanup of old files and directories
// -----------------------------------------------------------------------------
static void charon_cleanup_archive(const std::string& root, 
                            const Config& cfg, 
                            bool aggressive) noexcept {
    CHARON_LOG_DEBUG("charon", "Starting cleanup: root=%s aggressive=%s", 
              root.c_str(), aggressive ? "yes" : "no");
    
    std::vector<std::pair<time_t, std::string>> old_files;
    time_t now = time(nullptr);
    int64_t max_age_sec = static_cast<int64_t>(cfg.max_age_days) * 86400LL;
    
    static CharonDirectoryCleanup deleter;
    
    std::deque<std::pair<std::string, bool>> queue;
    queue.push_back({root, false});
    size_t depth = 0;
    
    while (!queue.empty() && !charon_shutdown.load(std::memory_order_acquire)) {
        if (++depth > constants::MAX_DIRECTORY_DEPTH) {
            CHARON_LOG_WARN("charon", "Directory depth exceeds limit (%zu), skipping deeper directories", 
                    constants::MAX_DIRECTORY_DEPTH);
            continue;
        }
        
        auto [path, is_date_dir] = queue.front();
        queue.pop_front();
        
        if (path.size() > constants::MAX_DIR_PATH_LENGTH) {
            CHARON_LOG_WARN("charon", "Path too long, skipping: %s", path.c_str());
            continue;
        }
        
        DIR* d = opendir(path.c_str());
        if (!d) {
            CHARON_LOG_WARN("charon", "Failed to open directory for cleanup: %s", path.c_str());
            continue;
        }
        
        bool has_children = false;
        struct dirent* de;
        
        while ((de = readdir(d))) {
            if (charon_shutdown.load(std::memory_order_acquire)) break;
            
            if (de->d_name[0] == '.' && 
               (de->d_name[1] == '\0' || 
               (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
                continue;
            }
            
            if (path.size() + 1 + strlen(de->d_name) + 1 >= PATH_MAX) {
                CHARON_LOG_WARN("charon", "Path too long, skipping: %s/%s", path.c_str(), de->d_name);
                continue;
            }
            
            std::string full = path + '/' + de->d_name;
            
            if (charon_contains_path_traversal(full) || !charon_validate_path_length(full)) {
                ++charon_metrics.invalid_paths_rejected;
                CHARON_LOG_WARN("security", "Skipping path with traversal: %s", full.c_str());
                continue;
            }
            
            struct stat st{};
            
            if (lstat(full.c_str(), &st) != 0) {
                CHARON_LOG_WARN("charon", "lstat failed in cleanup: %s", full.c_str());
                continue;
            }
            
            if (S_ISDIR(st.st_mode)) {
                int y = 0, m = 0, d_num = 0;
                bool child_is_date_dir = charon_parse_date_from_path(full, root, y, m, d_num);
                queue.push_back({full, child_is_date_dir});
                has_children = true;
                
            } else if (S_ISREG(st.st_mode)) {
                has_children = true;
                
                if (strncmp(de->d_name, ".charon.tmp.", 14) == 0 && 
                    now - st.st_mtime > cfg.temp_gc_age_sec) {
                    
                    CHARON_LOG_DEBUG("charon", "Removing old temp file: %s (age: %lds)", 
                             full.c_str(), now - st.st_mtime);
                    
                    if (unlink(full.c_str()) == 0) {
                        ++charon_metrics.temp_gc_removed;
                    } else {
                        CHARON_LOG_WARN("charon", "temp unlink failed %s : %s", 
                                full.c_str(), strerror(errno));
                    }
                } 
                else if (aggressive && is_date_dir && 
                        now - st.st_mtime > max_age_sec) {
                    old_files.emplace_back(st.st_mtime, full);
                }
            }
        }
        
        closedir(d);
        
        if (!has_children && path != root) {
            deleter.mark(path);
        }
    }
    
    if (aggressive && !old_files.empty()) {
        charon_cleanup_aggressive(old_files, cfg);
    }
    
    deleter.sweep();
    CHARON_LOG_DEBUG("charon", "Cleanup completed");
}

// -----------------------------------------------------------------------------
// Aggressive cleanup for low disk space situations
// -----------------------------------------------------------------------------
static void charon_cleanup_aggressive(const std::vector<std::pair<time_t, std::string>>& old_files,
                                     const Config& cfg) noexcept {
    CHARON_LOG_INFO("charon", "Found %zu old files for aggressive cleanup", old_files.size());
    time_t now = time(nullptr);
    
    std::vector<std::pair<time_t, std::string>> sorted_files = old_files;
    std::sort(sorted_files.begin(), sorted_files.end());
    
    size_t n = std::min(sorted_files.size(), static_cast<size_t>(cfg.cleanup_batch));
    
    for (size_t i = 0; i < n && !charon_shutdown.load(std::memory_order_acquire); ++i) {
        CHARON_LOG_DEBUG("charon", "Removing old file: %s (age: %lds)", 
                 sorted_files[i].second.c_str(), now - sorted_files[i].first);
        
        if (unlink(sorted_files[i].second.c_str()) == 0) {
            ++charon_metrics.cleanup_files;
            SecurityAudit::instance().log_operation("AGGRESSIVE_CLEANUP", sorted_files[i].second, "", true);
        } else {
            CHARON_LOG_WARN("charon", "failed to unlink old file %s : %s", 
                    sorted_files[i].second.c_str(), strerror(errno));
        }
    }
}

// -----------------------------------------------------------------------------
// Charon Vessel — Main service loops for scanning and cleaning
// -----------------------------------------------------------------------------
class CharonRotator {
    std::atomic<bool> running_{false};
    std::thread scanner_thread_;
    std::thread cleaner_thread_;
    CharonDirectoryCleanup dir_cleanup_;
    std::mutex shutdown_mtx_;
    std::condition_variable shutdown_cv_;

    void handle_config_reload() noexcept {
        if (charon_reload.exchange(false, std::memory_order_acq_rel)) {
            auto cfg = charon_load_config_from_env();
            if (!cfg) {
                CHARON_LOG_ERROR("charon", "Failed to reload config, keeping previous configuration");
                return;
            }
            charon_config.store(cfg);
            CHARON_LOG_INFO("charon", "Config reloaded via SIGHUP");
            
            SecurityAudit::instance().set_enabled(cfg->enable_audit_log);
            
            auto pool = g_charon_pool;
            if (pool) {
                pool->adjust_threads(cfg->copy_threads);
            }
        }
    }
    
    void apply_backoff_strategy(int failures, const Config& cfg) noexcept {
        if (failures <= 0) return;
        
        int max_backoff = std::min(cfg.rotation_sec * 5, 60);
        int backoff_sec = std::min(failures, max_backoff);
        
        CHARON_LOG_WARN("charon", "High rotation failure count (%d). Backing off for %d seconds...",
                failures, backoff_sec);
        
        std::this_thread::sleep_for(std::chrono::seconds(backoff_sec));
    }
    
    void charon_rotate_fresh(const Config& cfg) noexcept {
        ++charon_metrics.scan_iterations;
        
        auto files = charon_scan_fresh(cfg.fresh_path);
        charon_metrics.files_scanned += files.size();
        
        if (files.size() <= cfg.max_fresh) {
            CHARON_LOG_DEBUG("charon", "Only %zu files, below limit %zu", files.size(), cfg.max_fresh);
            return;
        }
        
        size_t n = files.size() - cfg.max_fresh;
        CHARON_LOG_INFO("charon", "Need to rotate %zu files (have %zu, limit %zu)", 
                n, files.size(), cfg.max_fresh);
        
        std::nth_element(files.begin(), files.begin() + n, files.end(),
                        [](auto& a, auto& b) { return a.first < b.first; });
        
        time_t now = time(nullptr);
        struct tm tm{};
        localtime_r(&now, &tm);
        
        for (size_t i = 0; i < n && !charon_shutdown.load(std::memory_order_acquire); ++i) {
            auto [old_mtime, src] = files[i];
            
            struct stat st{};
            if (lstat(src.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
                continue;
            }
            
            if (std::abs(st.st_mtime - old_mtime) > cfg.mtime_tolerance_sec) {
                CHARON_LOG_DEBUG("charon", "File modified since scan, skipping: %s", src.c_str());
                continue;
            }
            
            auto name_pos = src.rfind('/');
            if (name_pos == std::string::npos) continue;
            
            const char* name = src.c_str() + name_pos + 1;
            char dst[PATH_MAX];
            
            int len = snprintf(dst, sizeof(dst), "%s/%04d/%02d/%02d/%s",
                              cfg.archive_root.c_str(),
                              tm.tm_year + 1900, 
                              tm.tm_mon + 1, 
                              tm.tm_mday, 
                              name);
            
            if (len <= 0 || len >= PATH_MAX) {
                CHARON_LOG_WARN("charon", "Destination path too long: %s/%s", 
                        cfg.archive_root.c_str(), name);
                continue;
            }
            
            std::string dst_str(dst, len);
            
            if (!charon_validate_destination_path(dst_str, cfg.archive_root)) {
                ++charon_metrics.security_errors;
                SecurityAudit::instance().log_operation("INVALID_DEST_PATH", src, dst_str, false, "Path validation failed");
                CHARON_LOG_WARN("security", "Skipping rotation due to invalid destination path: %s", dst_str.c_str());
                continue;
            }
            
            CHARON_LOG_INFO("charon", "Rotating: %s -> %s", src.c_str(), dst_str.c_str());
            charon_atomic_rename(src, dst_str);
        }
    }

    void scanner_loop() noexcept {
        CHARON_LOG_INFO("charon", "scanner thread started");
        charon_block_signals_in_worker_threads();
       
        while (!charon_shutdown.load(std::memory_order_acquire)) {
            handle_config_reload();
           
            auto cfg_ptr = charon_config.load();
            if (!cfg_ptr) {
                std::this_thread::sleep_for(constants::WORKER_SHUTDOWN_POLL_INTERVAL);
                continue;
            }
           
            const Config& cfg = *cfg_ptr;
           
            int failures = g_rotation_failures.load(std::memory_order_acquire);
            if (failures > 0) {
                apply_backoff_strategy(failures, cfg);
               
                if (charon_shutdown.load(std::memory_order_acquire)) break;
               
                cfg_ptr = charon_config.load();
                if (!cfg_ptr) {
                    std::this_thread::sleep_for(constants::WORKER_SHUTDOWN_POLL_INTERVAL);
                    continue;
                }
            }
           
            charon_rotate_fresh(cfg);
           
            struct statvfs sv{};
            if (statvfs(cfg.archive_root.c_str(), &sv) == 0) {
                uint64_t total_blocks = sv.f_blocks;
                uint64_t avail_blocks = sv.f_bavail;
               
                if (total_blocks > 0) {
                    uint64_t used_pct = (total_blocks - avail_blocks) * 100ULL / total_blocks;
                    bool low_space = used_pct > cfg.disk_limit_pct;
                    charon_throttle_adaptive(low_space, cfg);
                }
            }

            const auto sleep_until = std::chrono::steady_clock::now() +
                                     std::chrono::seconds(cfg.rotation_sec);
            
            std::unique_lock<std::mutex> lk(shutdown_mtx_);
            shutdown_cv_.wait_until(lk, sleep_until, [] {
                return charon_shutdown.load(std::memory_order_acquire);
            });
        }
       
        CHARON_LOG_INFO("charon", "scanner thread stopped");
    }
    
    void cleaner_loop() noexcept {
        CHARON_LOG_INFO("charon", "cleaner thread started");
        charon_block_signals_in_worker_threads();
      
        auto last_cleanup = std::chrono::steady_clock::now();
      
        while (!charon_shutdown.load(std::memory_order_acquire)) {
            handle_config_reload();
          
            auto cfg_ptr = charon_config.load();
            if (!cfg_ptr) {
                std::this_thread::sleep_for(constants::WORKER_SHUTDOWN_POLL_INTERVAL);
                continue;
            }
          
            const Config& cfg = *cfg_ptr;
          
            auto now = std::chrono::steady_clock::now();
            auto minutes_since_last = std::chrono::duration_cast<std::chrono::minutes>(now - last_cleanup);
          
            if (minutes_since_last.count() >= cfg.cleanup_min) {
                bool aggressive = false;
              
                struct statvfs sv{};
                if (statvfs(cfg.archive_root.c_str(), &sv) == 0) {
                    uint64_t total_blocks = sv.f_blocks;
                    uint64_t avail_blocks = sv.f_bavail;
                  
                    if (total_blocks > 0) {
                        uint64_t used_pct = (total_blocks - avail_blocks) * 100ULL / total_blocks;
                        aggressive = used_pct > cfg.disk_limit_pct;
                        CHARON_LOG_DEBUG("charon", "Disk usage: %lu%% (threshold: %lu%%, aggressive: %s)",
                                 used_pct, cfg.disk_limit_pct, aggressive ? "yes" : "no");
                    }
                }
              
                charon_cleanup_archive(cfg.archive_root, cfg, aggressive);
              
                last_cleanup = now;
            }

            const auto sleep_until = std::chrono::steady_clock::now() +
                                     std::chrono::seconds(60);
            
            std::unique_lock<std::mutex> lk(shutdown_mtx_);
            shutdown_cv_.wait_until(lk, sleep_until, [] {
                return charon_shutdown.load(std::memory_order_acquire);
            });
        }
      
        CHARON_LOG_INFO("charon", "cleaner thread stopped");
    }

public:
    CharonRotator() = default;

    void force_notify_all() noexcept {
        {
            std::lock_guard<std::mutex> lk(shutdown_mtx_);
            shutdown_cv_.notify_all();
        }
        if (g_charon_pool) {
            g_charon_pool->force_notify();
        }
    }

    void start() noexcept {
        if (running_.exchange(true)) {
            CHARON_LOG_WARN("charon", "Charon already running");
            return;
        }
        
        CHARON_LOG_INFO("charon", "Starting Charon");
        
        auto cfg = charon_load_config_from_env();
        if (!cfg) {
            CHARON_LOG_ERROR("charon", "Failed to load configuration");
            running_.store(false);
            return;
        }
        
        charon_config.store(cfg);
        
        if (cfg->fresh_path.empty() || cfg->archive_root.empty()) {
            CHARON_LOG_ERROR("charon", "Invalid configuration: paths cannot be empty");
            running_.store(false);
            return;
        }
        
        if (cfg->use_syslog) {
            openlog("charon", LOG_PID | LOG_NDELAY, LOG_DAEMON);
            CHARON_LOG_INFO("charon", "Syslog logging initialized");
        }
        
        CHARON_LOG_INFO("charon", "Configuration loaded: fresh=%s, archive=%s, threads=%d", 
                cfg->fresh_path.c_str(), cfg->archive_root.c_str(), 
                cfg->copy_threads);
        
        CHARON_LOG_INFO("charon", "Security features: chroot=%s, capabilities=%s, memfd=%s",
                cfg->chroot_path.empty() ? "disabled" : "enabled",
                "hardened",
                cfg->use_memfd ? "enabled" : "disabled");
        
        SecurityAudit::instance().set_enabled(cfg->enable_audit_log);
        
        if (!charon_drop_privileges(*cfg)) {
            CHARON_LOG_ERROR("charon", "Failed to drop privileges");
            running_.store(false);
            return;
        }
        
        g_fresh_index.enable(cfg->use_xattr_index);
        
        g_charon_pool = std::make_shared<CharonWorkerPool>(cfg->copy_threads);
        charon_metrics.current_copy_threads.store(cfg->copy_threads);
        
        charon_install_signal_handlers();
        
        scanner_thread_ = std::thread([this] { scanner_loop(); });
        cleaner_thread_ = std::thread([this] { cleaner_loop(); });
        
#if defined(__linux__)
        pthread_setname_np(scanner_thread_.native_handle(), "charon-scanner");
        pthread_setname_np(cleaner_thread_.native_handle(), "charon-cleaner");
#endif
        
#ifdef __linux__
        g_systemd_notifier.notify_ready();
#endif
        
        CHARON_LOG_INFO("charon", "Charon started (PID=%d, threads=%d)",
                getpid(), cfg->copy_threads);
    }
    
    void stop() noexcept {
        if (!running_.exchange(false)) {
            CHARON_LOG_WARN("charon", "Charon not running");
            return;
        }
       
        CHARON_LOG_INFO("charon", "Stopping Charon");
       
        charon_shutdown.store(true, std::memory_order_release);
       
        force_notify_all();
       
#ifdef __linux__
        g_systemd_notifier.notify_stopping();
#endif
       
        if (scanner_thread_.joinable()) {
            scanner_thread_.join();
            CHARON_LOG_INFO("charon", "Scanner thread stopped gracefully");
        }
       
        if (cleaner_thread_.joinable()) {
            cleaner_thread_.join();
            CHARON_LOG_INFO("charon", "Cleaner thread stopped gracefully");
        }
       
        if (g_charon_pool) {
            g_charon_pool->stop();
            g_charon_pool.reset();
        }
       
        dir_cleanup_.sweep();
       
        CHARON_LOG_INFO("charon", "Final metrics: rotated=%lu, atomic_success=%lu, errors=%lu",
                charon_metrics.rotated_total.load(),
                charon_metrics.atomic_rename_success.load(),
                charon_metrics.errors.load());
       
        CHARON_LOG_INFO("charon", "Security stats: invalid_paths_rejected=%lu, security_errors=%lu",
                charon_metrics.invalid_paths_rejected.load(),
                charon_metrics.security_errors.load());
       
        CHARON_LOG_INFO("charon", "Charon stopped gracefully");
       
        if (charon_config.load() && charon_config.load()->use_syslog) {
            closelog();
        }
    }
    
    void force_rotate() noexcept {
        CHARON_LOG_INFO("charon", "Manual force rotation triggered");
        auto cfg_ptr = charon_config.load();
        if (!cfg_ptr) {
            CHARON_LOG_ERROR("charon", "No configuration available");
            return;
        }
        charon_rotate_fresh(*cfg_ptr);
        CHARON_LOG_INFO("charon", "Manual rotation completed");
    }
    
    void force_cleanup(bool aggressive = false) noexcept {
        CHARON_LOG_INFO("charon", "Manual force cleanup triggered (aggressive=%s)", 
                          aggressive ? "yes" : "no");
        auto cfg_ptr = charon_config.load();
        if (!cfg_ptr) {
            CHARON_LOG_ERROR("charon", "No configuration available");
            return;
        }
        charon_cleanup_archive(cfg_ptr->archive_root, *cfg_ptr, aggressive);
        CHARON_LOG_INFO("charon", "Manual cleanup completed");
    }
    
    bool is_running() const noexcept {
        return running_.load();
    }
};

static CharonRotator& charon_rotator_instance() { 
    static CharonRotator r; 
    return r; 
}

// -----------------------------------------------------------------------------
// System resource limits and security hardening
// -----------------------------------------------------------------------------
static void charon_set_resource_limits() noexcept {
#ifdef __linux__
    struct rlimit core_limit = {0, 0};
    setrlimit(RLIMIT_CORE, &core_limit);
    
    struct rlimit fsize_limit = {100ULL * 1024 * 1024 * 1024, 100ULL * 1024 * 1024 * 1024};
    setrlimit(RLIMIT_FSIZE, &fsize_limit);
    
    prctl(PR_SET_DUMPABLE, 0);
    
    CHARON_LOG_DEBUG("charon", "Resource limits and security settings applied");
#endif
}

// -----------------------------------------------------------------------------
// CLI Command implementations
// -----------------------------------------------------------------------------

// Double fork daemonization (classic Unix daemon)
static void daemonize() noexcept {
    pid_t pid = fork();
    if (pid < 0) {
        std::exit(1);
    }
    if (pid > 0) {
        std::exit(0);  // Parent exits
    }

    if (setsid() < 0) {
        std::exit(1);
    }

    pid = fork();
    if (pid < 0) {
        std::exit(1);
    }
    if (pid > 0) {
        std::exit(0);  // First child exits
    }

    umask(027);
    if (chdir("/") != 0) {
       
    }

    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);
    }
}

// Command: start
static int cmd_start() noexcept {
    if (mkdir(PID_DIR, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "ERROR: Cannot create %s: %s\n", PID_DIR, strerror(errno));
        return 1;
    }

    if (access(PID_FILE, F_OK) == 0) {
        FILE* f = fopen(PID_FILE, "r");
        if (f) {
            pid_t pid;
            if (fscanf(f, "%d", &pid) == 1 && kill(pid, 0) == 0) {
                fprintf(stderr, "ERROR: Charon already running (PID %d)\n", pid);
                fclose(f);
                return 1;
            }
            fclose(f);
        }
        unlink(PID_FILE);
    }

    daemonize();

    openlog("charon", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    try {
        g_pid_lock = std::make_unique<PidFileLock>(PID_FILE);
    } catch (...) {
        syslog(LOG_ERR, "Failed to acquire pidfile lock");
        closelog();
        return 1;
    }

    g_is_daemon.store(true, std::memory_order_relaxed);

    charon_install_signal_handlers();

#ifdef __linux__
    g_systemd_notifier.notify_ready();
#endif

    CHARON_LOG_INFO("charon", "Daemon started successfully");

    charon_rotator_instance().start();

    while (!charon_shutdown.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    charon_rotator_instance().force_notify_all();

    charon_rotator_instance().stop();
    g_pid_lock.reset();

    CHARON_LOG_INFO("charon", "Charon daemon exited successfully");
    closelog();
    
    return 0;
}

// Command: stop
static int cmd_stop() noexcept {
    FILE* f = fopen(PID_FILE, "r");
    if (!f) {
        fprintf(stderr, "INFO: Charon not running (no pidfile)\n");
        return 0;
    }

    pid_t pid;
    if (fscanf(f, "%d", &pid) != 1) {
        fclose(f);
        fprintf(stderr, "ERROR: Invalid pidfile\n");
        unlink(PID_FILE);
        return 1;
    }
    fclose(f);

    if (kill(pid, SIGTERM) != 0) {
        if (errno == ESRCH) {
            unlink(PID_FILE);
            printf("INFO: Process not found, stale pidfile removed\n");
            return 0;
        }
        perror("kill(SIGTERM)");
        return 1;
    }

    for (int i = 0; i < 100; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        if (kill(pid, 0) != 0) {
            if (errno == ESRCH) {
                unlink(PID_FILE);
                printf("Charon stopped gracefully\n");
                return 0;
            }
        }

        if (i == 20) kill(pid, SIGINT);
        if (i == 100) fprintf(stderr, "WARNING: Process %d still running after 10s...\n", pid);
    }

    fprintf(stderr, "WARNING: Process %d not responding, sending SIGKILL\n", pid);

    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        perror("kill(SIGKILL)");
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    unlink(PID_FILE);

    printf("Charon force stopped\n");
    return 0;
}

// Command: status
static int cmd_status() noexcept {
    FILE* f = fopen(PID_FILE, "r");
    if (!f) {
        printf("Service status: STOPPED\n");
        // Still print metrics if possible
        char buf[4096];
        if (charon_get_metrics(buf, sizeof(buf)) > 0) {
            printf("%s\n", buf);
        }
        return 3;
    }

    pid_t pid;
    if (fscanf(f, "%d", &pid) != 1) {
        fclose(f);
        printf("Service status: STOPPED (corrupted pidfile)\n");
        return 3;
    }
    fclose(f);

    char buf[4096];
    charon_get_metrics(buf, sizeof(buf));

    if (kill(pid, 0) == 0) {
        printf("Service status: RUNNING (PID %d)\n", pid);
        printf("%s\n", buf);
        return 0;
    } else {
        unlink(PID_FILE);
        printf("Service status: STOPPED (stale pidfile removed)\n");
        printf("%s\n", buf);
        return 3;
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

int charon_get_metrics_cpp(char* buf, size_t sz) noexcept {
    int n = snprintf(buf, sz,
        "rotated_total %" PRIu64 "\n"
        "cross_device_moves %" PRIu64 "\n"
        "atomic_rename_success %" PRIu64 "\n"
        "atomic_rename_failed %" PRIu64 "\n"
        "copy_threads %d\n"
        "active_copies %d\n"
        "queued_tasks %d\n"
        "backpressure_events %" PRIu64 "\n"
        "cleanup_dirs %" PRIu64 "\n"
        "cleanup_files %" PRIu64 "\n"
        "temp_gc_removed %" PRIu64 "\n"
        "errors %" PRIu64 "\n"
        "out_of_space %" PRIu64 "\n"
        "scan_iterations %" PRIu64 "\n"
        "files_scanned %" PRIu64 "\n"
        "rotation_failures %d\n"
        "copy_file_range_calls %" PRIu64 "\n"
        "fallback_copy_calls %" PRIu64 "\n"
        "copy_bytes_total %" PRIu64 "\n"
        "queue_full_rejections %" PRIu64 "\n"
        "copy_operations_time_ms %" PRIu64 "\n"
        "symlinks_skipped %" PRIu64 "\n"
        "hardlinks_skipped %" PRIu64 "\n"
        "oversized_files_skipped %" PRIu64 "\n"
        "security_errors %" PRIu64 "\n"
        "invalid_paths_rejected %" PRIu64 "\n"
        "integer_overflow_checks %" PRIu64 "\n"
        "buffer_clears %" PRIu64 "\n"
        "fsync_calls %" PRIu64 "\n"
        "io_uring_ops %" PRIu64 "\n"
        "adaptive_buffer_adjustments %" PRIu64 "\n"
        "audit_log_size %zu\n",
        charon_metrics.rotated_total.load(),
        charon_metrics.cross_device_moves.load(),
        charon_metrics.atomic_rename_success.load(),
        charon_metrics.atomic_rename_failed.load(),
        charon_metrics.current_copy_threads.load(),
        charon_metrics.active_copies.load(),
        charon_metrics.queued_tasks.load(),
        charon_metrics.backpressure_events.load(),
        charon_metrics.cleanup_dirs.load(),
        charon_metrics.cleanup_files.load(),
        charon_metrics.temp_gc_removed.load(),
        charon_metrics.errors.load(),
        charon_metrics.out_of_space.load(),
        charon_metrics.scan_iterations.load(),
        charon_metrics.files_scanned.load(),
        g_rotation_failures.load(),
        charon_metrics.copy_file_range_calls.load(),
        charon_metrics.fallback_copy_calls.load(),
        charon_metrics.copy_bytes_total.load(),
        charon_metrics.queue_full_rejections.load(),
        charon_metrics.copy_operations_time_ms.load(),
        charon_metrics.symlinks_skipped.load(),
        charon_metrics.hardlinks_skipped.load(),
        charon_metrics.oversized_files_skipped.load(),
        charon_metrics.security_errors.load(),
        charon_metrics.invalid_paths_rejected.load(),
        charon_metrics.integer_overflow_checks.load(),
        charon_metrics.buffer_clears.load(),
        charon_metrics.fsync_calls.load(),
        charon_metrics.io_uring_ops.load(),
        charon_metrics.adaptive_buffer_adjustments.load(),
        SecurityAudit::instance().size()
    );
    
    return (n < 0 || static_cast<size_t>(n) >= sz) ? -1 : n;
}

extern "C" int charon_get_metrics(char* buf, size_t sz) noexcept {
    return charon_get_metrics_cpp(buf, sz);
}

// -----------------------------------------------------------------------------
// Charon Vessel — Entry point and CLI handling
// -----------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s {start|stop|status|force-rotate|force-cleanup|daemon}\n", argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "start") {
        return cmd_start();
    } else if (cmd == "stop") {
        return cmd_stop();
    } else if (cmd == "status") {
        return cmd_status();
    } else if (cmd == "force-rotate") {
        // Existing manual control (requires root check if needed)
        charon_rotator_instance().force_rotate();
        printf("Force rotation completed\n");
        return 0;
    } else if (cmd == "force-cleanup") {
        bool aggressive = (argc > 2 && std::string(argv[2]) == "aggressive");
        charon_rotator_instance().force_cleanup(aggressive);
        printf("Force cleanup completed (aggressive: %s)\n", aggressive ? "yes" : "no");
        return 0;
    } else if (cmd == "daemon") {
        // Direct foreground run for debugging
        // Reuse existing initialization without daemonize
        // (keep original logic or call cmd_start without daemonize)
        fprintf(stderr, "Direct daemon mode not changed in this refactor\n");
        return 1;
    }

    fprintf(stderr, "ERROR: Unknown command: %s\n", cmd.c_str());
    return 1;
}

// -----------------------------------------------------------------------------
// C API for external integration and monitoring
// -----------------------------------------------------------------------------
extern "C" {
    void charon_start_background_rotator() noexcept { 
        charon_set_resource_limits();
        charon_rotator_instance().start(); 
    }
    
    void charon_stop_background_rotator() noexcept { 
        charon_rotator_instance().stop(); 
    }
}
