#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sched.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <limits.h>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <system_error>
#include <stdexcept>

constexpr size_t STACK_SIZE = 1024 * 1024;

// RAII-обертка для безопасного закрытия файловых дескрипторов
class FileDescriptor {
    int fd_;
public:
    explicit FileDescriptor(int fd = -1) noexcept : fd_(fd) {}
    ~FileDescriptor() { close_fd(); }

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    FileDescriptor(FileDescriptor&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }

    int get() const noexcept { return fd_; }

    void close_fd() noexcept {
        if (fd_ != -1) {
            ::close(fd_);
            fd_ = -1;
        }
    }
};

struct ChildArgs {
    int pipe_read_fd;
    int pipe_write_fd;
    std::string rootfs;
    std::vector<char*> cmd_argv;
};

// Проверка системных вызовов
void check_syscall(int result, const std::string& msg) {
    if (result == -1) {
        throw std::system_error(errno, std::generic_category(), msg);
    }
}

// Запись в системные файлы /proc
void write_proc_file(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось открыть файл: " + path);
    }
    file << content;
    if (!file) {
        throw std::runtime_error("Ошибка записи в файл: " + path);
    }
}

// Функция промежуточного дочернего процесса (уже внутри CLONE_NEWUSER)
int child_fn(void* arg) {
    auto* args = static_cast<ChildArgs*>(arg);

    try {
        // Закрываем дескриптор записи
        ::close(args->pipe_write_fd);

        // Ожидаем, пока родитель настроит uid_map и gid_map
        char ch;
        ssize_t bytes = ::read(args->pipe_read_fd, &ch, 1);
        ::close(args->pipe_read_fd);

        if (bytes != 0) {
            throw std::runtime_error("Ошибка синхронизации через pipe");
        }

        // Теперь процесс имеет CAP_SYS_ADMIN внутри user namespace.
        // Изолируем остальные 5 пространств имен (как это делает утилита unshare):
        int unshare_flags = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWPID;
        check_syscall(::unshare(unshare_flags), "unshare остальные пространства");

        // Делаем fork(), чтобы новый процесс вошел в созданный PID namespace как PID 1
        pid_t init_pid = ::fork();
        check_syscall(init_pid, "fork для PID 1");

        if (init_pid > 0) {
            // Промежуточный процесс ждет завершения главного процесса контейнера (PID 1)
            int status = 0;
            ::waitpid(init_pid, &status, 0);
            return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
        }

        // === ДАЛЕЕ ВЫПОЛНЯЕТСЯ ПРОЦЕСС С PID 1 ВНУТРИ КОНТЕЙНЕРА ===

        // 1. Изолируем имя хоста (UTS namespace)
        const std::string hostname = "container";
        check_syscall(::sethostname(hostname.c_str(), hostname.size()), "sethostname");

        // 2. Переводим корневую ФС в режим MS_PRIVATE (защита хоста)
        check_syscall(::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr), "mount MS_PRIVATE");

        // 3. Делаем каталог rootfs точкой монтирования (требование pivot_root)
        check_syscall(::mount(args->rootfs.c_str(), args->rootfs.c_str(), nullptr, MS_BIND | MS_REC, nullptr), "mount bind rootfs");
        check_syscall(::chdir(args->rootfs.c_str()), "chdir rootfs");

        // 4. Создаем временную директорию для старого корня и меняем корневую ФС
        if (::mkdir("old_root", 0755) == -1 && errno != EEXIST) {
            check_syscall(-1, "mkdir old_root");
        }
        check_syscall(::syscall(SYS_pivot_root, ".", "old_root"), "pivot_root");
        check_syscall(::chdir("/"), "chdir /");

        // 5. Монтируем изолированный /proc для нового PID namespace
        if (::mkdir("/proc", 0555) == -1 && errno != EEXIST) {
            check_syscall(-1, "mkdir /proc");
        }
        check_syscall(::mount("proc", "/proc", "proc", 0, nullptr), "mount /proc");

        // 6. Отключаем и удаляем старый корень хоста
        check_syscall(::umount2("/old_root", MNT_DETACH), "umount2 /old_root");
        check_syscall(::rmdir("/old_root"), "rmdir /old_root");

        // Настраиваем базовый PATH
        ::setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);

        // Запускаем целевую команду
        ::execvp(args->cmd_argv[0], args->cmd_argv.data());
        check_syscall(-1, "execvp (" + std::string(args->cmd_argv[0]) + ")");

    } catch (const std::exception& ex) {
        std::cerr << "[Контейнер] Ошибка: " << ex.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main(int argc, char* argv[]) {
    if (argc < 5 || std::string(argv[1]) != "run" || std::string(argv[2]) != "--rootfs") {
        std::cerr << "Использование: " << argv[0] << " run --rootfs <путь_к_rootfs> <команда> [аргументы...]\n";
        return EXIT_FAILURE;
    }

    try {
        int pipe_fds[2];
        check_syscall(::pipe(pipe_fds), "pipe");

        FileDescriptor read_end(pipe_fds[0]);
        FileDescriptor write_end(pipe_fds[1]);

        // Разрешаем канонический путь к rootfs
        char resolved_path[PATH_MAX];
        if (::realpath(argv[3], resolved_path) == nullptr) {
            check_syscall(-1, "realpath (" + std::string(argv[3]) + ")");
        }

        ChildArgs args;
        args.pipe_read_fd = read_end.get();
        args.pipe_write_fd = write_end.get();
        args.rootfs = resolved_path;

        for (int i = 4; i < argc; ++i) {
            args.cmd_argv.push_back(argv[i]);
        }
        args.cmd_argv.push_back(nullptr);

        // Выделяем стек через std::vector
        std::vector<char> stack(STACK_SIZE);
        char* stack_top = stack.data() + stack.size();

        // Шаг 1: Создаем ТОЛЬКО user namespace (аналог unshare --user)
        int flags = CLONE_NEWUSER | SIGCHLD;

        pid_t child_pid = ::clone(child_fn, stack_top, flags, &args);
        check_syscall(child_pid, "clone (CLONE_NEWUSER)");

        // В родителе закрываем конец канала на чтение
        read_end.close_fd();

        std::string proc_dir = "/proc/" + std::to_string(child_pid);

        // Шаг 2: Настраиваем маппинг UID и GID (аналог --map-root-user)
        write_proc_file(proc_dir + "/setgroups", "deny");
        write_proc_file(proc_dir + "/uid_map", "0 " + std::to_string(::getuid()) + " 1\n");
        write_proc_file(proc_dir + "/gid_map", "0 " + std::to_string(::getgid()) + " 1\n");

        // Шаг 3: Разблокируем дочерний процесс
        write_end.close_fd();

        int status = 0;
        check_syscall(::waitpid(child_pid, &status, 0), "waitpid");

        return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;

    } catch (const std::exception& ex) {
        std::cerr << "[Родитель] Критическая ошибка: " << ex.what() << '\n';
        return EXIT_FAILURE;
    }
}


