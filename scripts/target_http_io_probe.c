#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Link the actual firmware object against the shipped libc. A private Unix
 * socketpair exercises stdio read-to-write transitions without a listener. */
extern int http_request_begin(int fd);
extern void http_request_allow_body(void);
extern FILE *http_client_fopen(int fd);

int main(void)
{
	const char request[] = "POST / HTTP/1.0\r\n\r\nBODY";
	const char response[] = "REPLY";
	char line[64], body[4], received[sizeof(response)];
	struct timeval timeout = { 5, 0 };
	int sockets[2] = { -1, -1 }, result = 1;
	FILE *stream = NULL;
	size_t used = 0;
	ssize_t count;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) ||
	    setsockopt(sockets[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
	    http_request_begin(sockets[0])) goto done;
	stream = http_client_fopen(sockets[0]);
	if (!stream) goto done;
	sockets[0] = -1; /* stream owns this descriptor. */
	if (write(sockets[1], request, sizeof(request) - 1) != (ssize_t)(sizeof(request) - 1)) goto done;
	if (!fgets(line, sizeof(line), stream) || strcmp(line, "POST / HTTP/1.0\r\n") ||
	    !fgets(line, sizeof(line), stream) || strcmp(line, "\r\n")) goto done;
	http_request_allow_body();
	if (fread(body, 1, sizeof(body), stream) != sizeof(body) || memcmp(body, "BODY", sizeof(body))) goto done;
	if (fwrite(response, 1, sizeof(response), stream) != sizeof(response) || fflush(stream)) goto done;
	while (used < sizeof(received)) {
		count = read(sockets[1], received + used, sizeof(received) - used);
		if (count < 0 && errno == EINTR) continue;
		if (count <= 0) goto done;
		used += (size_t)count;
	}
	if (memcmp(received, response, sizeof(response))) goto done;
	result = 0;
done:
	if (stream) fclose(stream);
	if (sockets[0] >= 0) close(sockets[0]);
	if (sockets[1] >= 0) close(sockets[1]);
	if (!result) puts("target HTTP cookie stream: actual firmware object/private socketpair PASS");
	else fprintf(stderr, "target HTTP cookie stream failed: %s\n", strerror(errno));
	return result;
}
