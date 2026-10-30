#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Run with the shipped libc through qemu-user. All writes stay in a newly
 * created private directory; no router process or privileged API is invoked. */
int main(void)
{
	char directory[] = "/tmp/k2p-abi-XXXXXX";
	const char contents[] = "K2P target ABI\n";
	char buffer[sizeof(contents)];
	struct stat st;
	struct statvfs fs;
	struct timespec now;
	struct pollfd ready;
	struct dirent *entry;
	DIR *stream = NULL;
	int parent = -1, file = -1, iterator = -1, linked = -1, found = 0, result = 1;
	int created = 0, descriptor_flags;
	const char *step = "mkdtemp";
	if (!mkdtemp(directory)) goto done;
	created = 1;
	step = "open directory";
	parent = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (parent < 0) goto done;
	step = "openat";
	file = openat(parent, "probe", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (file < 0) goto done;
	step = "CLOEXEC and IO";
	descriptor_flags = fcntl(file, F_GETFD);
	if (descriptor_flags < 0 || !(descriptor_flags & FD_CLOEXEC) ||
	    write(file, contents, sizeof(contents)) != (ssize_t)sizeof(contents) ||
	    lseek(file, 0, SEEK_SET) != 0 ||
	    read(file, buffer, sizeof(buffer)) != (ssize_t)sizeof(buffer) ||
	    memcmp(contents, buffer, sizeof(buffer))) goto done;
	step = "fstatat/fstatvfs";
	if (fstatat(parent, "probe", &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode) ||
	    (st.st_mode & 0777) != 0600 || fstatvfs(parent, &fs) || !fs.f_bsize) goto done;
	step = "monotonic clock/poll";
	ready.fd = file;
	ready.events = POLLIN | POLLOUT;
	ready.revents = 0;
	if (clock_gettime(CLOCK_MONOTONIC, &now) || poll(&ready, 1, 0) < 0 ||
	    !(ready.revents & POLLOUT)) goto done;
	step = "fdopendir";
	iterator = dup(parent);
	if (iterator < 0 || !(stream = fdopendir(iterator))) goto done;
	iterator = -1; /* stream owns the duplicated descriptor. */
	while ((entry = readdir(stream))) if (!strcmp(entry->d_name, "probe")) found = 1;
	if (!found) goto done;
	closedir(stream);
	stream = NULL;
	step = "symlinkat/NOFOLLOW";
	if (symlinkat("probe", parent, "link")) goto done;
	errno = 0;
	linked = openat(parent, "link", O_RDONLY | O_NOFOLLOW);
	if (linked >= 0 || errno != ELOOP) goto done;
	step = "renameat/unlinkat";
	if (renameat(parent, "probe", parent, "renamed") ||
	    unlinkat(parent, "renamed", 0) || unlinkat(parent, "link", 0)) goto done;
	step = "fmemopen";
	{
		FILE *memory = fmemopen(buffer, sizeof(buffer), "r");
		if (!memory) goto done;
		found = fgetc(memory) == contents[0] && !ferror(memory);
		if (fclose(memory) || !found) goto done;
	}
	step = "waitid WNOWAIT";
	{
		pid_t child = fork(), reaped;
		int status;
		siginfo_t child_info;
		if (child < 0) goto done;
		if (!child) _exit(17);
		memset(&child_info, 0, sizeof(child_info));
		do { found = waitid(P_PID, (id_t)child, &child_info, WEXITED | WNOWAIT); }
		while (found && errno == EINTR);
		do { reaped = waitpid(child, &status, 0); } while (reaped < 0 && errno == EINTR);
		if (found || child_info.si_pid != child || child_info.si_code != CLD_EXITED ||
		    child_info.si_status != 17 || reaped != child ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 17) goto done;
	}
	result = 0;
done:
	if (result) fprintf(stderr, "target ABI failed at %s: %s\n", step, strerror(errno));
	if (stream) closedir(stream);
	if (iterator >= 0) close(iterator);
	if (linked >= 0) close(linked);
	if (file >= 0) close(file);
	if (parent >= 0) {
		unlinkat(parent, "probe", 0);
		unlinkat(parent, "renamed", 0);
		unlinkat(parent, "link", 0);
		close(parent);
	}
	if (created) rmdir(directory);
	if (!result) puts("target libc ABI: openat/fstatat/fdopendir/unlinkat/renameat/NOFOLLOW/CLOEXEC/monotonic/poll PASS");
	return result;
}
