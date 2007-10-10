#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <sys/poll.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <netdb.h>
#include <netinet/in.h>

static void die_usage(void)
{
	fputs("Usage: tcprdr [ -4 | -6 ] localport host [ remoteport ]\n", stderr);
	exit(1);
}

static int wanted_pf = PF_UNSPEC;

static int sock_listen_tcp(const char * const listenaddr, const char * const port)
{
	int err, sock;
	struct addrinfo hints = {
		.ai_protocol = IPPROTO_TCP,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_PASSIVE | AI_NUMERICHOST
	};

	hints.ai_family = wanted_pf;

	struct addrinfo *a, *addr;
	int one = 1;

	err = getaddrinfo(listenaddr, port, &hints, &addr);
	if (err) {
		fprintf(stderr, "Fatal: getaddrinfo(): %s\n", gai_strerror(err));
	        exit(1);
	}

	for (a = addr; a != NULL ; a = a->ai_next) {
		sock = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
		if (sock < 0) {
			perror("socket");
			continue;
		}

		if (-1 == setsockopt(sock, SOL_SOCKET,SO_REUSEADDR,&one,sizeof one))
			perror("setsockopt");


		if (bind(sock, a->ai_addr, a->ai_addrlen) == 0)
			break; /* success */

		perror("bind");
		close(sock);
		sock = -1;
	}

	if ((sock >= 0) && listen(sock ,20))
		perror("listen");

	freeaddrinfo(addr);
	return sock;
}


static int sock_connect_tcp(const char * const remoteaddr, const char * const port)
{
	int err, sock;
	struct addrinfo hints = {
		.ai_protocol = IPPROTO_TCP,
		.ai_socktype = SOCK_STREAM
	};
	struct addrinfo *a, *addr;

	hints.ai_family = wanted_pf;

	err = getaddrinfo(remoteaddr, port, &hints, &addr);
	if (err) {
		fprintf(stderr, "Fatal: getaddrinfo(): %s\n", gai_strerror(err));
	        exit(1);
	}

	for (a=addr; a != NULL; a = a->ai_next) {
		sock = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
		if (sock < 0) {
			perror("socket");
			continue;
		}

		if (connect(sock, a->ai_addr, a->ai_addrlen) == 0)
			break; /* success */

		perror("connect()");
		close(sock);
		sock = -1;
	}

	freeaddrinfo(addr);
	return sock;
}


static size_t do_write(const int fd, char *buf, const size_t len)
{
	size_t offset = 0;

	while (offset < len) {
		size_t written;
		ssize_t bw = write(fd, buf+offset, len - offset);
		if (bw < 0 ) {
			perror("write");
			return 0;
		}

		written = (size_t) bw;
		offset += written;
	}
	return offset;
}


static void copyfd_io(int fd_zero, int fd_one)
{
	struct pollfd fds[] = { { .events = POLLIN }, { .events = POLLIN }};

	fds[0].fd = fd_zero;
	fds[1].fd = fd_one;

	for (;;) {
		int readfd, writefd;

		readfd = -1;
		writefd = -1;

		switch(poll(fds, 2, -1)) {
		case -1:
			if (errno == EINTR)
				continue;
			perror("poll");
			return;
		case 0:
			/* should not happen, we requested infinite wait */
			fputs("Timed out?!", stderr);
			return;
		}

		if (fds[0].revents & POLLHUP) return;
		if (fds[1].revents & POLLHUP) return;

		if (fds[0].revents & POLLIN) {
			readfd = fds[0].fd;
			writefd = fds[1].fd;
		} else if (fds[1].revents & POLLIN) {
			readfd = fds[1].fd;
			writefd = fds[0].fd;
		}

		if (readfd>=0 && writefd >= 0) {
			char buf[4096];
			ssize_t len;

			len = read(readfd, buf, sizeof buf);
			if (!len) return;
			if (len < 0) {
				if (errno == EINTR)
					continue;

				perror("read");
				return;
			}
			if (!do_write(writefd, buf, len)) return;
		} else {
			/* Should not happen,  at least one fd must have POLLHUP and/or POLLIN set */
			fputs("Warning: no useful poll() event", stderr);
		}
	}
}


static int parse_args(int argc, char *const argv[])
{
	int i;
	for (i = 0; i < argc; i++) {
		if (argv[i][0] != '-')
			return i;
		switch(argv[i][1]) {
			case '4': wanted_pf = PF_INET; break;
			case '6': wanted_pf = PF_INET6; break;
			default:
				die_usage();
		}
	}
	return i;
}


/* try to chroot; don't complain if chroot doesn't work */
static void do_chroot(void)
{
	if (chroot("/var/empty") == 0) {
		/* chroot ok, chdir, setuid must not fail */
		if (chdir("/")) {
			perror("chdir /var/empty");
			exit(1);
		}
		setgid(65535);
		if (setuid(65535)) {
			perror("setuid");
			exit(1);
		}
	}
}


int main(int argc, char *argv[])
{
	struct sockaddr sa;
	int args;
	int listensock, remotesock, connsock;
	socklen_t salen = sizeof sa;

	if (argc < 3)
		die_usage();

	--argc;
	++argv;

	args = parse_args(argc, argv);

	argc -= args;
	argv += args;

	if (argc <= 2) /* we need at least 2 more arguments (srcport, hostname) */
		die_usage();

	listensock = sock_listen_tcp(NULL, argv[0]);
	if (listensock < 0)
		return 1;

	do_chroot();

	while ((remotesock = accept(listensock, &sa, &salen)) < 0)
		perror("accept");

					 /* destport given? if no, use srcport */
	connsock = sock_connect_tcp(argv[1], argv[2] ? argv[2]:argv[0]);
	if (connsock < 0)
	       return 1;
	copyfd_io(connsock, remotesock);
	close(connsock);
	close(remotesock);

	return 0;
}

