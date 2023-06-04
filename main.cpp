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
#include "ELF64/fix.h"
#include "include/pmparser.h"

using namespace std;

static pid_t pid;

static pid_t find_pid(const char *process_name) {
    int id;
    pid_t pid = -1;
    DIR *dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];

    struct dirent *entry;
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

static bool pvm(uintptr_t address, void *buffer, size_t size, bool iswrite) {
    if (!pid || !address)
        return false;

    iovec local[1];
    iovec remote[1];
    local[0].iov_base = buffer;
    local[0].iov_len = size;
    remote[0].iov_base = (void *) address;
    remote[0].iov_len = size;

    long bytes = syscall((iswrite ? __NR_process_vm_writev : __NR_process_vm_readv), pid, local, 1, remote, 1, 0);
    return bytes == size;
}

int main(int argc, char *argv[]) {
    const char *pkg = nullptr, *so = nullptr;
    int opt;
    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        switch (opt) {
            case 'p':
                pkg = optarg;
                break;
            case 's':
                so = optarg;
                break;
            default:
                printf("Usage: %s [-p 包名] [-s so名字或路径]\n", argv[0]);
                break;
        }
    }
    //pkg = "com.tencent.ig";
    //so = "libUE4.so";
    if (pkg == nullptr || so == nullptr) {
        printf("Usage: %s [-p 包名] [-s so名字或路径]\n", argv[0]);
        return 0;
    }

    pid = find_pid(pkg);
    if (pid == -1) {
        printf("未找到进程: %s\n", pkg);
        return 0;
    }
    printf("找到进程: %s, pid: %d\n", pkg, pid);

    uintptr_t start = 0, end = 0;
    procmaps_iterator *maps = pmparser_parse(pid);

    if (maps == NULL) {
        printf("[map]: cannot parse the memory map of %d\n", pid);
        return -1;
    }

    //iterate over areas
    procmaps_struct *maps_tmp = NULL;

    while ((maps_tmp = pmparser_next(maps)) != NULL) {
        if (strstr(maps_tmp->pathname, so) != nullptr) {
            if (!start) {
                start = (uintptr_t) maps_tmp->addr_start;
            }
            end = (uintptr_t) maps_tmp->addr_end;
        }
    }

    //mandatory: should free the list
    pmparser_free(maps);

    if (start == 0 || end == 0) {
        printf("未找到so: %s\n", so);
        return 0;
    }
    printf("找到so: %s, start: %lx, end: %lx\n", so, start, end);

    size_t size = end - start;
    printf("so大小: %ld\n", size);

    char *buffer = new char[size];
    memset(buffer, 0, size);

    for (int i = 0; i < size; i += 4096) {
        pvm(start + i, buffer + i, 4096, false);
    }

    string tempPath = "/sdcard/"s + so + ".temp";
    string outPath = "/sdcard/"s + so + ".out";

    int fd = open(tempPath.c_str(), O_WRONLY | O_CREAT, 0666);
    if (fd == -1) {
        perror("创建文件失败\n");
        return 0;
    }
    write(fd, buffer, size);
    close(fd);
    delete[] buffer;

    fix_so(tempPath.c_str(), outPath.c_str(), start);
    remove(tempPath.c_str());

    printf("修复完成, 修复后的so路径: %s\n", outPath.c_str());
    return 0;
}
