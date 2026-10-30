/* Isolated CI child only: exercise real Linux DAC as uid/gid99, no capabilities. */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <linux/capability.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    if (argc < 2 || geteuid() != 0) {
        fprintf(stderr, "UID probe requires a privileged isolated Linux child\n");
        return 77;
    }
    if (setgroups(0, NULL) || setgid(99) || setuid(99) ||
        getuid() != 99 || geteuid() != 99 || getgid() != 99 || getegid() != 99) {
        perror("drop uid/gid99");
        return 78;
    }
    if (syscall(SYS_capget, &header, data) != 0 ||
        data[0].effective || data[0].permitted || data[0].inheritable ||
        data[1].effective || data[1].permitted || data[1].inheritable) {
        fprintf(stderr, "UID probe retained capabilities or capget failed\n");
        return 79;
    }
    if (getgroups(0, NULL) != 0) {
        fprintf(stderr, "UID probe retained supplementary groups\n");
        return 79;
    }
    fprintf(stderr, "UID_PROBE uid=99 euid=99 gid=99 egid=99 groups=0 capabilities=0\n");
    execvp(argv[1], argv + 1);
    perror("UID probe exec");
    return 80;
}
