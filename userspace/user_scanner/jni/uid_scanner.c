#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <android/log.h>
#include <time.h>
#include <stdarg.h>

#define LOG_TAG "User_UID_Scanner"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Paths and constants
#define USER_DATA_BASE_PATH "/data/user_de"
#define KSU_UID_LIST_PATH "/data/misc/user_uid/uid_list"
#define PROC_COMM_PATH "/proc/ksu_uid_scanner"
#define PID_FILE_PATH "/data/misc/user_uid/uid_scanner.pid"
#define LOG_FILE_PATH "/data/misc/user_uid/uid_scanner.log"
#define CONFIG_FILE_PATH "/data/misc/user_uid/uid_scanner.conf"

#define MAX_PACKAGE_NAME 256
#define MAX_PATH_LEN 512
#define MAX_LOG_SIZE (1024 * 1024)  // 1MB
#define MAX_USERS 8
#define MAX_RETRIES 3
#define RETRY_DELAY 60

typedef enum {
    LANG_EN = 0,
    LANG_ZH = 1
} language_t;

struct scanner_config {
    language_t language;
    int multi_user_scan;
    int scan_interval;
    int log_level;
    int auto_scan;
};

struct uid_data {
    int uid;
    char package[MAX_PACKAGE_NAME];
    struct uid_data *next;
};

typedef struct {
    const char *en;
    const char *zh;
} message_t;

// Global variables
static volatile int manual_scan_flag = 0;
static volatile int should_exit = 0;
static volatile int should_reload = 0;
static struct uid_data *uid_list_head = NULL;
static int log_fd = -1;

static struct scanner_config config = {
    .language = LANG_EN,
    .multi_user_scan = 0,
    .scan_interval = 5,
    .log_level = 1,
    .auto_scan = 0
};

int save_config(void);

// message dictionary
static const message_t messages[] = {
    {"Signal %d received", "收到信号 %d"},
    {"Reload signal", "重载信号"},
    {"User signal", "用户信号"},
    {"Log rotated", "日志轮转"},
    {"Fork failed: %s", "Fork失败: %s"},
    {"setsid failed: %s", "setsid失败: %s"},
    {"Second fork failed: %s", "第二次fork失败: %s"},
    {"chdir failed: %s", "目录切换失败: %s"},
    {"PID file create failed %s: %s", "PID文件创建失败 %s: %s"},
    {"PID file created: %d", "PID文件已创建: %d"},
    {"Daemon not running", "守护进程未运行"},
    {"Stopping daemon (PID: %d)", "停止守护进程 (PID: %d)"},
    {"Kill signal failed: %s", "终止信号失败: %s"},
    {"Daemon stopped", "守护进程已停止"},
    {"Force terminating", "强制终止中"},
    {"Daemon killed", "守护进程已杀死"},
    {"Cannot stop daemon", "无法停止守护进程"},
    {"Restarting daemon", "重启守护进程"},
    {"Cannot stop old daemon", "无法停止旧守护进程"},
    {"Starting new daemon", "启动新守护进程"},
    {"Status: Not running", "状态: 未运行"},
    {"Status: Running (PID: %d)", "状态: 运行中 (PID: %d)"},
    {"Recent logs:", "最近日志:"},
    {"Status: Stopped (stale PID)", "状态: 已停止 (陈旧PID)"},
    {"Sending reload signal (PID: %d)", "发送重载信号 (PID: %d)"},
    {"Reload signal sent", "重载信号已发送"},
    {"Reload signal failed: %s", "重载信号失败: %s"},
    {"Directory open failed %s: %s", "目录打开失败 %s: %s"},
    {"Scan started", "扫描开始"},
    {"Package name too long: %s", "包名过长: %s"},
    {"File stat failed %s: %s", "文件状态获取失败 %s: %s"},
    {"Memory allocation failed", "内存分配失败"},
    {"Scan complete, found %d packages", "扫描完成，发现 %d 个包"},
    {"Whitelist file open failed %s: %s", "白名单文件打开失败 %s: %s"},
    {"Whitelist written %d entries", "白名单写入 %d 个条目"},
    {"Kernel comm file open failed %s: %s", "内核通信文件打开失败 %s: %s"},
    {"Kernel comm write failed %s: %s", "内核通信写入失败 %s: %s"},
    {"Kernel notified", "内核已通知"},
    {"Performing scan and update", "执行扫描和更新"},
    {"Scan failed", "扫描失败"},
    {"Whitelist write failed", "白名单写入失败"},
    {"Scan completed successfully", "扫描成功完成"},
    {"Whitelist not found: %s", "白名单未找到: %s"},
    {"Current whitelist:", "当前白名单:"},
    {"One-time scan", "一次性扫描"},
    {"Invalid argument: %s", "无效参数: %s"},
    {"Daemon already running", "守护进程已运行"},
    {"Starting daemon", "启动守护进程"},
    {"Daemon startup failed", "守护进程启动失败"},
    {"Daemon started", "守护进程已启动"},
    {"Reload request received", "收到重载请求"},
    {"Kernel rescan request", "内核重扫描请求"},
    {"Daemon exiting", "守护进程退出中"},
    {"Daemon exited", "守护进程已退出"},
    {"Config loaded", "配置已加载"},
    {"Config saved", "配置已保存"},
    {"Config load failed: %s", "配置加载失败: %s"},
    {"Config save failed: %s", "配置保存失败: %s"},
    {"Language switched to English", "语言切换到英文"},
    {"Language switched to Chinese", "语言切换到中文"},
    {"Multi-user scan enabled", "多用户扫描启用"},
    {"Multi-user scan disabled", "多用户扫描禁用"},
    {"Scanning directory: %s", "扫描目录: %s"},
    {"Found %d users", "发现 %d 个用户"},
    {"Using fallback user detection", "使用备用用户检测"},
    {"Auto scan enabled", "自动扫描启用"},
    {"Auto scan disabled", "自动扫描禁用"},
    {"Auto scan disabled, daemon loaded", "自动扫描禁用，守护进程已加载"},
    {"Auto scan disabled, skipping", "自动扫描禁用，跳过"},
    {"Auto scan disabled, ignoring kernel request", "自动扫描禁用，忽略内核请求"},
    {"Retry attempt %d/%d", "重试 %d/%d"},
    {"Max retries reached, waiting %d seconds", "达到最大重试次数，等待 %d 秒"},
    {"Operation failed after retries", "重试后操作失败"},
    {"Auto scan disabled, operation not allowed", "自动扫描禁用，操作不被允许"},
    {"Manual scan requested, ignoring auto_scan setting", "手动扫描请求，忽略自动扫描设置"}
};

#define MSG_COUNT (sizeof(messages) / sizeof(messages[0]))

const char* get_message(int msg_id) {
    if (msg_id < 0 || msg_id >= (int)MSG_COUNT) {
        return "Unknown message";
    }
    return (config.language == LANG_ZH) ? messages[msg_id].zh : messages[msg_id].en;
}

void write_log(const char *level, int msg_id, ...) {
    char buffer[1024];
    char formatted_msg[1024];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    va_list args;
    
    va_start(args, msg_id);
    vsnprintf(formatted_msg, sizeof(formatted_msg), get_message(msg_id), args);
    va_end(args);
    
    strftime(buffer, 64, "[%H:%M:%S]", tm_info);
    snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), " %s: %s", level, formatted_msg);
    
    if (log_fd != -1) {
        dprintf(log_fd, "%s\n", buffer);
        fsync(log_fd);
    }
    
    if (strcmp(level, "ERROR") == 0) {
        LOGE("%s", formatted_msg);
    } else {
        LOGI("%s", formatted_msg);
    }
}

// Retry wrapper for operations
int retry_operation(int (*operation)(void), const char *op_name) {
    (void)op_name;
    for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        int result = operation();
        if (result == 0) {
            return 0; // Success
        }
        
        if (attempt < MAX_RETRIES) {
            write_log("WARN", 69, attempt, MAX_RETRIES); // Retry attempt X/Y
            sleep(1);
        } else {
            write_log("ERROR", 70, RETRY_DELAY); // Max retries reached
            sleep(RETRY_DELAY);
            write_log("ERROR", 71); // Operation failed after retries
        }
    }
    return -1;
}

void ensure_directory_exists(void) {
    const char *path = "/data/misc/user_uid";
    struct stat st;

    if (stat(path, &st) != 0) {
        if (mkdir(path, 0777) != 0) {
            LOGE("Failed to create directory %s: %s", path, strerror(errno));
            return;
        }
    }

    if (chmod(path, 0777) != 0) {
        LOGE("Failed to chmod directory %s: %s", path, strerror(errno));
    }
}

void parse_config_line(const char *key, const char *value) {
    if (strcmp(key, "language") == 0) {
        config.language = (strcmp(value, "zh") == 0) ? LANG_ZH : LANG_EN;
    } else if (strcmp(key, "multi_user_scan") == 0) {
        config.multi_user_scan = atoi(value);
    } else if (strcmp(key, "scan_interval") == 0) {
        config.scan_interval = atoi(value);
        if (config.scan_interval < 1) config.scan_interval = 5;
    } else if (strcmp(key, "log_level") == 0) {
        config.log_level = atoi(value);
    } else if (strcmp(key, "auto_scan") == 0) {
        config.auto_scan = atoi(value);
    }
}

int load_config(void) {
    FILE *fp = fopen(CONFIG_FILE_PATH, "r");
    if (!fp) {
        write_log("WARN", 56, "配置文件不存在，使用默认配置");
        return save_config();
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        
        if (line[0] == '#' || line[0] == '\0') continue;
        
        char key[64], value[64];
        if (sscanf(line, "%63[^=]=%63s", key, value) == 2) {
            parse_config_line(key, value);
        }
    }
    
    fclose(fp);
    write_log("INFO", 54); // Config loaded
    write_log("INFO", config.auto_scan ? 64 : 65); // 记录当前自动扫描状态
    return 0;
}

int save_config(void) {
    ensure_directory_exists();
    
    FILE *fp = fopen(CONFIG_FILE_PATH, "w");
    if (!fp) {
        write_log("ERROR", 57, strerror(errno)); // Config save failed
        return -1;
    }
    
    fprintf(fp, "# UID Scanner Configuration\n");
    fprintf(fp, "# Language: en (English) or zh (Chinese)\n");
    fprintf(fp, "language=%s\n", (config.language == LANG_ZH) ? "zh" : "en");
    fprintf(fp, "# Multi-user scanning: 0=disabled, 1=enabled\n");
    fprintf(fp, "multi_user_scan=%d\n", config.multi_user_scan);
    fprintf(fp, "# Scan interval in seconds\n");
    fprintf(fp, "scan_interval=%d\n", config.scan_interval);
    fprintf(fp, "# Log level: 0=minimal, 1=normal, 2=verbose\n");
    fprintf(fp, "log_level=%d\n", config.log_level);
    fprintf(fp, "# Auto scan: 0=disabled, 1=enabled\n");
    fprintf(fp, "auto_scan=%d\n", config.auto_scan);
    
    fclose(fp);
    write_log("INFO", 55); // Config saved
    return 0;
}

void set_language(language_t lang) {
    config.language = lang;
    save_config();
    write_log("INFO", (lang == LANG_ZH) ? 59 : 58);
}

void set_multi_user_scan(int enabled) {
    config.multi_user_scan = enabled;
    save_config();
    write_log("INFO", enabled ? 60 : 61);
}

void set_auto_scan(int enabled) {
    config.auto_scan = enabled;
    save_config();
    write_log("INFO", enabled ? 64 : 65);
}

void signal_handler(int sig) {
    switch (sig) {
        case SIGTERM:
        case SIGINT:
            should_exit = 1;
            write_log("INFO", 0, sig);
            break;
        case SIGHUP:
            should_reload = 1;
            write_log("INFO", 1);
            break;
        case SIGUSR1:
            should_reload = 1;
            write_log("INFO", 2);
            break;
    }
}

void manage_log_file(void) {
    struct stat st;
    if (log_fd == -1 || fstat(log_fd, &st) != 0) return;
    
    if (st.st_size > MAX_LOG_SIZE) {
        close(log_fd);
        char backup_path[MAX_PATH_LEN];
        snprintf(backup_path, sizeof(backup_path), "%s.old", LOG_FILE_PATH);
        rename(LOG_FILE_PATH, backup_path);
        log_fd = open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd != -1) {
            write_log("INFO", 3); // Log rotated
        }
    }
}

void setup_daemon_stdio(void) {
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
}

int daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) {
        LOGE(get_message(4), strerror(errno));
        return -1;
    }
    if (pid > 0) exit(0);
    
    if (setsid() < 0) {
        LOGE(get_message(5), strerror(errno));
        return -1;
    }
    
    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) {
        LOGE(get_message(6), strerror(errno));
        return -1;
    }
    if (pid > 0) exit(0);
    
    umask(0);
    if (chdir("/") < 0) {
        LOGE(get_message(7), strerror(errno));
        return -1;
    }
    
    setup_daemon_stdio();
    return 0;
}

int write_pid_file(void) {
    ensure_directory_exists();
    FILE *fp = fopen(PID_FILE_PATH, "w");
    if (!fp) {
        write_log("ERROR", 8, PID_FILE_PATH, strerror(errno));
        return -1;
    }
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
    write_log("INFO", 9, getpid());
    return 0;
}

pid_t read_pid_file(void) {
    FILE *fp = fopen(PID_FILE_PATH, "r");
    if (!fp) return 0;
    
    pid_t pid = 0;
    if (fscanf(fp, "%d", &pid) != 1) pid = 0;
    fclose(fp);
    return pid;
}

int is_daemon_running(void) {
    pid_t pid = read_pid_file();
    if (pid <= 0) return 0;
    
    if (kill(pid, 0) == 0) {
        return 1;
    } else {
        unlink(PID_FILE_PATH);
        return 0;
    }
}

int stop_daemon(void) {
    pid_t pid = read_pid_file();
    if (pid <= 0) {
        printf("%s\n", get_message(10));
        return 0;
    }
    
    printf(get_message(11), pid);
    printf("\n");
    
    if (kill(pid, SIGTERM) != 0) {
        printf(get_message(12), strerror(errno));
        printf("\n");
        return -1;
    }
    
    // Wait up to 30 seconds
    for (int i = 0; i < 30; i++) {
        if (kill(pid, 0) != 0) {
            printf("%s\n", get_message(13));
            unlink(PID_FILE_PATH);
            return 0;
        }
        sleep(1);
    }
    
    printf("%s\n", get_message(14));
    if (kill(pid, SIGKILL) == 0) {
        printf("%s\n", get_message(15));
        unlink(PID_FILE_PATH);
        return 0;
    }
    
    printf("%s\n", get_message(16));
    return -1;
}

int restart_daemon(void) {
    printf("%s\n", get_message(17));
    stop_daemon();
    sleep(2);
    
    if (is_daemon_running()) {
        printf("%s\n", get_message(18));
        return -1;
    }
    
    printf("%s\n", get_message(19));
    return 0;
}

void show_status(void) {
    pid_t pid = read_pid_file();
    if (pid <= 0) {
        printf("%s\n", get_message(20));
        return;
    }
    
    if (kill(pid, 0) == 0) {
        printf(get_message(21), pid);
        printf("\n");
        
        if (access(LOG_FILE_PATH, R_OK) == 0) {
            printf("\n%s\n", get_message(22));
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "tail -n 10 %s", LOG_FILE_PATH);
            system(cmd);
        }
    } else {
        printf("%s\n", get_message(23));
        unlink(PID_FILE_PATH);
    }
}

void reload_daemon(void) {
    pid_t pid = read_pid_file();
    if (pid <= 0 || kill(pid, 0) != 0) {
        printf("%s\n", get_message(10));
        return;
    }
    
    printf(get_message(24), pid);
    printf("\n");
    
    if (kill(pid, SIGUSR1) == 0) {
        printf("%s\n", get_message(25));
    } else {
        printf(get_message(26), strerror(errno));
        printf("\n");
    }
}

int get_users_from_pm(char user_dirs[][MAX_PATH_LEN], int max_users) {
    FILE *fp = popen("pm list users 2>/dev/null | grep 'UserInfo{' | sed 's/.*UserInfo{\\([0-9]*\\):.*/\\1/'", "r");
    if (!fp) return 0;
    
    int user_count = 0;
    char line[64];
    while (fgets(line, sizeof(line), fp) && user_count < max_users) {
        int user_id = atoi(line);
        if (user_id >= 0) {
            snprintf(user_dirs[user_count], MAX_PATH_LEN, "%s/%d", USER_DATA_BASE_PATH, user_id);
            if (access(user_dirs[user_count], F_OK) == 0) {
                user_count++;
            }
        }
    }
    
    pclose(fp);
    return user_count;
}

int get_users_from_directory_scan(char user_dirs[][MAX_PATH_LEN], int max_users) {
    DIR *dir = opendir(USER_DATA_BASE_PATH);
    if (!dir) {
        write_log("ERROR", 27, USER_DATA_BASE_PATH, strerror(errno));
        snprintf(user_dirs[0], MAX_PATH_LEN, "%s/0", USER_DATA_BASE_PATH);
        return 1;
    }
    
    int user_count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && user_count < max_users) {
        if (entry->d_type == DT_DIR) {
            char *endptr;
            long user_id = strtol(entry->d_name, &endptr, 10);
            if (*endptr == '\0' && strlen(entry->d_name) > 0 && user_id >= 0) {
                snprintf(user_dirs[user_count], MAX_PATH_LEN, "%s/%s", USER_DATA_BASE_PATH, entry->d_name);
                user_count++;
            }
        }
    }
    closedir(dir);
    
    if (user_count == 0) {
        snprintf(user_dirs[0], MAX_PATH_LEN, "%s/0", USER_DATA_BASE_PATH);
        user_count = 1;
    }
    
    return user_count;
}

int get_user_directories(char user_dirs[][MAX_PATH_LEN], int max_users) {
    if (!config.multi_user_scan) {
        snprintf(user_dirs[0], MAX_PATH_LEN, "%s/0", USER_DATA_BASE_PATH);
        return 1;
    }
    
    int user_count = get_users_from_pm(user_dirs, max_users);
    if (user_count > 0) return user_count;
    
    return get_users_from_directory_scan(user_dirs, max_users);
}

void free_uid_list(void) {
    struct uid_data *current = uid_list_head;
    while (current) {
        struct uid_data *next = current->next;
        free(current);
        current = next;
    }
    uid_list_head = NULL;
}

struct uid_data* create_uid_entry(int uid, const char *package_name) {
    struct uid_data *data = malloc(sizeof(struct uid_data));
    if (!data) {
        write_log("ERROR", 31);
        return NULL;
    }
    
    data->uid = uid;
    strncpy(data->package, package_name, MAX_PACKAGE_NAME - 1);
    data->package[MAX_PACKAGE_NAME - 1] = '\0';
    data->next = uid_list_head;
    return data;
}

int scan_single_directory(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        write_log("ERROR", 27, dir_path, strerror(errno));
        return 0;
    }
    
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (should_exit) break;
        
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (entry->d_type != DT_DIR) continue;
        
        if (strlen(entry->d_name) >= MAX_PACKAGE_NAME) {
            write_log("WARN", 29, entry->d_name);
            continue;
        }
        
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
        
        struct stat st;
        if (stat(path, &st) != 0) {
            write_log("ERROR", 30, path, strerror(errno));
            continue;
        }
        
        struct uid_data *data = create_uid_entry(st.st_uid, entry->d_name);
        if (data) {
            uid_list_head = data;
            count++;
        }
    }
    
    closedir(dir);
    return count;
}

int perform_uid_scan(void) {
    char user_dirs[MAX_USERS][MAX_PATH_LEN];
    int total_count = 0;
    
    free_uid_list();
    
    int user_count = get_user_directories(user_dirs, MAX_USERS);
    if (user_count <= 0) return -1;
    
    write_log("INFO", 28);
    write_log("INFO", 63, user_count);
    
    for (int i = 0; i < user_count && !should_exit; i++) {
        write_log("INFO", 62, user_dirs[i]);
        total_count += scan_single_directory(user_dirs[i]);
    }
    
    write_log("INFO", 32, total_count);
    return total_count;
}

int write_uid_whitelist(void) {
    ensure_directory_exists();
    
    FILE *fp = fopen(KSU_UID_LIST_PATH, "w");
    if (!fp) {
        write_log("ERROR", 33, KSU_UID_LIST_PATH, strerror(errno));
        return -1;
    }
    
    int count = 0;
    struct uid_data *current = uid_list_head;
    while (current) {
        fprintf(fp, "%d %s\n", current->uid, current->package);
        current = current->next;
        count++;
    }
    
    fclose(fp);
    write_log("INFO", 34, count);
    return count;
}

void notify_kernel_update(void) {
    int fd = open(PROC_COMM_PATH, O_WRONLY);
    if (fd < 0) {
        write_log("ERROR", 35, PROC_COMM_PATH, strerror(errno));
        return;
    }
    
    if (write(fd, "UPDATED", 7) != 7) {
        write_log("ERROR", 36, PROC_COMM_PATH, strerror(errno));
    } else {
        write_log("INFO", 37);
    }
    
    close(fd);
}

int check_kernel_request(void) {
    FILE *fp = fopen(PROC_COMM_PATH, "r");
    if (!fp) return 0;
    
    char status[16];
    int result = 0;
    if (fgets(status, sizeof(status), fp) != NULL) {
        result = (strncmp(status, "RESCAN", 6) == 0);
    }
    
    fclose(fp);
    return result;
}

// Retry wrapper functions
int scan_operation(void) {
    return perform_uid_scan() < 0 ? -1 : 0;
}

int write_operation(void) {
    return write_uid_whitelist() < 0 ? -1 : 0;
}

void perform_scan_update(void) {
    if (!config.auto_scan && !manual_scan_flag) {
        write_log("WARN", 72); // Auto scan disabled, operation not allowed
        return;
    }

    write_log("INFO", 38);
    
    if (retry_operation(scan_operation, "scan") != 0) {
        write_log("ERROR", 39);
        return;
    }
    
    if (retry_operation(write_operation, "write") != 0) {
        write_log("ERROR", 40);
        return;
    }
    
    notify_kernel_update();
    write_log("INFO", 41);
}

void perform_manual_scan_update(void) {
    manual_scan_flag = 1; 
    write_log("INFO", 73); // Manual scan requested, ignoring auto_scan setting
    write_log("INFO", 38);
    
    if (retry_operation(scan_operation, "scan") != 0) {
        write_log("ERROR", 39);
        return;
    }
    
    if (retry_operation(write_operation, "write") != 0) {
        write_log("ERROR", 40);
        return;
    }
    
    notify_kernel_update();
    write_log("INFO", 41);
}

void print_usage(const char *prog) {
    if (config.language == LANG_ZH) {
        printf("用法: %s [选项]\n", prog);
        printf("KSU UID 扫描器 - 管理UID白名单\n\n");
        printf("选项:\n");
        printf("  start                启动守护进程\n");
        printf("  stop                 停止守护进程\n");
        printf("  restart              重启守护进程\n");
        printf("  status               显示守护进程状态\n");
        printf("  reload               重新加载守护进程配置\n");
        printf("  -s, --scan           执行一次扫描并退出 (忽略auto_scan设置)\n");
        printf("  -l, --list           列出当前UID白名单\n");
        printf("  --lang <en|zh>       设置语言 (英文|中文)\n");
        printf("  --multi-user <0|1>   设置多用户扫描 (0=禁用, 1=启用)\n");
        printf("  --auto-scan <0|1>    设置自动扫描 (0=禁用, 1=启用)\n");
        printf("  --config             显示当前配置\n");
        printf("  -h, --help           显示此帮助信息\n");
    } else {
        printf("Usage: %s [options]\n", prog);
        printf("KSU UID Scanner - Manage UID whitelist\n\n");
        printf("Options:\n");
        printf("  start                Start daemon\n");
        printf("  stop                 Stop daemon\n");
        printf("  restart              Restart daemon\n");
        printf("  status               Show daemon status\n");
        printf("  reload               Reload daemon config\n");
        printf("  -s, --scan           Perform one scan and exit (ignore auto_scan setting)\n");
        printf("  -l, --list           List current UID whitelist\n");
        printf("  --lang <en|zh>       Set language\n");
        printf("  --multi-user <0|1>   Set multi-user scanning\n");
        printf("  --auto-scan <0|1>    Set auto scanning\n");
        printf("  --config             Show current config\n");
        printf("  -h, --help           Show this help\n");
    }
}

void list_whitelist(void) {
    FILE *fp = fopen(KSU_UID_LIST_PATH, "r");
    if (!fp) {
        printf(get_message(42), strerror(errno));
        printf("\n");
        return;
    }
    
    printf("%s\n", get_message(43));
    printf("%-8s %-40s\n", "UID", (config.language == LANG_ZH) ? "包名" : "Package");
    printf("%-8s %-40s\n", "--------", "----------------------------------------");
    
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        int uid;
        char package[256];
        if (sscanf(line, "%d %255s", &uid, package) == 2) {
            printf("%-8d %-40s\n", uid, package);
        }
    }
    fclose(fp);
}

void show_config(void) {
    if (config.language == LANG_ZH) {
        printf("当前配置:\n");
        printf("  语言: %s\n", (config.language == LANG_ZH) ? "中文" : "英文");
        printf("  多用户扫描: %s\n", config.multi_user_scan ? "启用" : "禁用");
        printf("  自动扫描: %s\n", config.auto_scan ? "启用" : "禁用");
        printf("  扫描间隔: %d 秒\n", config.scan_interval);
        printf("  日志级别: %d\n", config.log_level);
    } else {
        printf("Current Configuration:\n");
        printf("  Language: %s\n", (config.language == LANG_ZH) ? "Chinese" : "English");
        printf("  Multi-user scan: %s\n", config.multi_user_scan ? "Enabled" : "Disabled");
        printf("  Auto scan: %s\n", config.auto_scan ? "Enabled" : "Disabled");
        printf("  Scan interval: %d seconds\n", config.scan_interval);
        printf("  Log level: %d\n", config.log_level);
    }
}

int handle_config_command(int argc, char *argv[]) {
    if (strcmp(argv[1], "--lang") == 0) {
        if (argc < 3) return 1;
        if (strcmp(argv[2], "zh") == 0) {
            set_language(LANG_ZH);
        } else if (strcmp(argv[2], "en") == 0) {
            set_language(LANG_EN);
        } else {
            return 1;
        }
        return 0;
    } else if (strcmp(argv[1], "--multi-user") == 0) {
        if (argc < 3) return 1;
        int value = atoi(argv[2]);
        if (value != 0 && value != 1) return 1;
        set_multi_user_scan(value);
        return 0;
    } else if (strcmp(argv[1], "--auto-scan") == 0) {
        if (argc < 3) return 1;
        int value = atoi(argv[2]);
        if (value != 0 && value != 1) return 1;
        set_auto_scan(value);
        return 0;
    } else if (strcmp(argv[1], "--config") == 0) {
        show_config();
        return 0;
    }
    return -1;
}

int handle_single_command(int argc, char *argv[]) {
    (void)argc;
    if (strcmp(argv[1], "-s") == 0 || strcmp(argv[1], "--scan") == 0) {
        printf("%s\n", get_message(44));
        manual_scan_flag = 1;
        perform_manual_scan_update();
        return 0;
    } else if (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--list") == 0) {
        list_whitelist();
        return 0;
    } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    } else if (strcmp(argv[1], "status") == 0) {
        show_status();
        return 0;
    } else if (strcmp(argv[1], "stop") == 0) {
        return stop_daemon();
    } else if (strcmp(argv[1], "reload") == 0) {
        reload_daemon();
        return 0;
    }
    return -1;
}

void setup_signal_handlers(void) {
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGUSR1, signal_handler);
    signal(SIGPIPE, SIG_IGN);
}

void init_daemon_logging(void) {
    ensure_directory_exists();
    log_fd = open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

void cleanup_daemon_resources(void) {
    write_log("INFO", 52);
    free_uid_list();
    unlink(PID_FILE_PATH);
    if (log_fd != -1) close(log_fd);
    write_log("INFO", 53);
}

void run_daemon_loop(void) {
    load_config();
    
    write_log("INFO", 49);
    
    if (!config.auto_scan) {
        write_log("INFO", 66);
    } else {
        perform_scan_update();
    }
    
    while (!should_exit) {
        if (should_reload) {
            load_config();
            
            if (!config.auto_scan) {
                write_log("INFO", 67);
            } else {
                write_log("INFO", 50);
                perform_scan_update();
            }
            should_reload = 0;
        }
        
        if (check_kernel_request()) {
            if (!config.auto_scan) {
                write_log("INFO", 68);
            } else {
                write_log("INFO", 51);
                perform_scan_update();
            }
        }
        
        manage_log_file();
        
        int sleep_iterations = config.scan_interval * 10;
        for (int i = 0; i < sleep_iterations && !should_exit && !should_reload; i++) {
            usleep(100000);
        }
    }
}

int main(int argc, char *argv[]) {
    load_config();
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    int result = handle_config_command(argc, argv);
    if (result >= 0) return result;
    
    result = handle_single_command(argc, argv);
    if (result >= 0) return result;
    
    if (strcmp(argv[1], "restart") == 0) {
        if (restart_daemon() != 0) return 1;
    } else if (strcmp(argv[1], "start") != 0) {
        printf(get_message(45), argv[1]);
        printf("\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (is_daemon_running()) {
        printf("%s\n", get_message(46));
        return 1;
    }
    
    printf("%s\n", get_message(47));
    if (daemonize() != 0) {
        printf("%s\n", get_message(48));
        return 1;
    }
    
    init_daemon_logging();
    if (write_pid_file() != 0) exit(1);
    setup_signal_handlers();
    run_daemon_loop();
    cleanup_daemon_resources();
    return 0;
}
