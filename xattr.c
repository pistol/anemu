#include <unistd.h>
#include <sys/syscall.h>

int setxattr (const char *path, const char *name,
              void *value, size_t size, int flags) {
    return syscall(__NR_setxattr, path, name, value, size, flags);
}

int fsetxattr (int filedes, const char *name,
               void *value, size_t size, int flags) {
    return syscall(__NR_fsetxattr, filedes, name, value, size, flags);
}

ssize_t getxattr (const char *path, const char *name,
                  void *value, size_t size) {
    return syscall(__NR_getxattr, path, name, value, size);
}

ssize_t fgetxattr (int filedes, const char *name,
                   void *value, size_t size) {
    return syscall(__NR_fgetxattr, filedes, name, value, size);
}
