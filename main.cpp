#include <dirent.h>
#include <cstdio>
#include <cstring>
#include <getopt.h>
#include <asm-generic/unistd.h>
#include <unistd.h>
#include <linux/uio.h>
#include <asm-generic/fcntl.h>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include "ELF64/fix.h"
#include "lsplt.hpp"
#include "argparse.hpp"

using namespace std;

static pid_t pid;

static pid_t find_pid(const char* process_name) {
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE* fp;
    char filename[32];
    char cmdline[256];

    struct dirent* entry;
    if (process_name == NULL) {
        return -1;
    }
    dir = opendir("/proc");
    if (dir == NULL) {
        return -1;
    }
    while ((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                if (strcmp(process_name, cmdline) == 0) {
                    pid = id;
                    break;
                }
            }
        }
    }
    closedir(dir);
    return pid;
}

static bool pvm(uintptr_t address, void* buffer, size_t size, bool iswrite) {
    if (!pid || !address)
        return false;

    iovec local[1];
    iovec remote[1];
    local[0].iov_base = buffer;
    local[0].iov_len = size;
    remote[0].iov_base = (void*)address;
    remote[0].iov_len = size;

    long bytes = syscall((iswrite ? __NR_process_vm_writev : __NR_process_vm_readv), pid, local, 1, remote, 1, 0);
    return bytes == size;
}

uintptr_t getModuleBasePerfect(int pid, const char* module_name) {
    uintptr_t result = 0;
    auto maps = lsplt::MapInfo::Scan(std::to_string(pid));
    for (auto it = maps.begin(); it != maps.end(); ++it) {
        if (it->path.find(module_name) != std::string::npos && it->perms & PROT_EXEC) {
            if (it != maps.begin()) {
                auto prev_it = std::prev(it);
                if (prev_it->path.find(module_name) != std::string::npos) {
                    result = prev_it->start;
                    break;
                }
            }
        }
    }
    return result;
}


int main(int argc, char* argv[]) {
    bool need_fix = true;
    std::string pkg, so;
    uintptr_t start = 0, end = 0;

    argparse::ArgumentParser program("SoDumper");

    program.add_argument("-p", "--pkg")
           .help("包名")
           .action([&](const auto& value) { pkg = value; })
           .required();

    program.add_argument("-s", "--so")
           .help("so名字或路径")
           .action([&](const auto& value) { so = value; });

    program.add_argument("-a", "--start")
           .help("dump起始地址")
           .action([&](const auto& value) { sscanf(value.c_str(), "%lx", &start); });

    program.add_argument("-b", "--end")
           .help("dump结束地址")
           .action([&](const auto& value) { sscanf(value.c_str(), "%lx", &end); });

    program.add_argument("-n", "--nofix")
           .help("不修复so")
           .default_value(true)
           .implicit_value(false)
           .action([&](const auto&) { need_fix = false; });

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        exit(1);
    }

    if (so.empty()) {
        if (start == 0 || end == 0) {
            printf("请指定so名字或路径或起始地址和结束地址\n");
            return -1;
        }
    }

    pid = find_pid(pkg.c_str());
    if (pid == -1) {
        printf("未找到进程: %s\n", pkg.c_str());
        return 0;
    }
    printf("找到进程: %s, pid: %d\n", pkg.c_str(), pid);

    if (start == 0 || end == 0) {
        auto maps = lsplt::MapInfo::Scan(std::to_string(pid));
        for (auto it = maps.begin(); it != maps.end(); ++it) {
            if (!start) {
                if (it->path.find(so) != std::string::npos && it->perms & PROT_EXEC) {
                    start = it->start;
                    if (it != maps.begin()) {
                        auto prev_it = std::prev(it);
                        if (prev_it->path.find(so) != std::string::npos) {
                            start = prev_it->start;
                        }
                        auto prev_prev_it = std::prev(prev_it);
                        if (prev_prev_it->path.find(so) != std::string::npos) {
                            start = prev_prev_it->start;
                        }
                    }
                }
            }
            if (!end && start) {
                if (it->path.find(so) == std::string::npos) {
                    auto next_it = std::next(it);

                    if (next_it != maps.end() && next_it->path.find(so) == std::string::npos) {
                        auto next_next_it = std::next(next_it);
                        if (next_next_it != maps.end() && next_next_it->path.find(so) == std::string::npos) {
                            auto prev_it = std::prev(it);
                            if (prev_it->path.find(so) != std::string::npos) {
                                end = it->path.find("[anon:.bss]") != std::string::npos ? it->end : prev_it->end;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    if (start == 0 || end == 0) {
        printf("未找到so: %s\n", so.c_str());
        return 0;
    }
    printf("找到so: %s, start: %lx, end: %lx\n", so.c_str(), start, end);

    size_t size = end - start;
    printf("so大小: %ld\n", size);

    auto buffer = make_unique<char[]>(size);

    memset(buffer.get(), 0, size);

    for (int i = 0; i < size; i += 4096) {
        pvm(start + i, buffer.get() + i, 4096, false);
    }

    string tempPath = "/sdcard/"s + so + ".temp";
    string outPath = "/sdcard/"s + so + ".out";

    if (need_fix) {
        int fd = open(tempPath.c_str(), O_WRONLY | O_CREAT, 0666);
        if (fd == -1) {
            perror("创建文件失败\n");
            return 0;
        }
        write(fd, buffer.get(), size);
        close(fd);

        fix_so(tempPath.c_str(), outPath.c_str(), start);
        remove(tempPath.c_str());

        printf("修复完成, 修复后的so路径: %s\n", outPath.c_str());
    } else {
        int fd = open(outPath.c_str(), O_WRONLY | O_CREAT, 0666);
        if (fd == -1) {
            perror("创建文件失败\n");
            return 0;
        }
        write(fd, buffer.get(), size);
        close(fd);
        printf("dump完成, dump后的so路径: %s\n", outPath.c_str());
    }
    return 0;
}
