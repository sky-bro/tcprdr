#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netdb.h>
#include <netinet/in.h>

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT      19
#endif

static void die_usage(void)
{
	fputs("Usage: tcprdr [ -4 | -6 ] [ -t ] localport host [ remoteport ]\n", stderr);
	exit(1);
}

static int wanted_pf = PF_UNSPEC;
static bool tproxy = false;

static const char *getxinfo_strerr(int err)
{
	const char *errstr;
	if (err == EAI_SYSTEM)
		errstr = strerror(errno);
	else
		errstr = gai_strerror(err);
	return errstr;
}

static void xgetaddrinfo(const char *node, const char *service,
			const struct addrinfo *hints,
			struct addrinfo **res)
{
	int err = getaddrinfo(node, service, hints, res);
	if (err) {
		const char *errstr = getxinfo_strerr(err);
		fprintf(stderr, "Fatal: getaddrinfo(%s:%s): %s\n", node ? node: "", service ? service: "", errstr);
	        exit(1);
	}
}


static void xgetnameinfo(const struct sockaddr *sa, socklen_t salen,
			char *host, size_t hostlen,
			char *serv, size_t servlen, int flags)
{
	int err = getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
	if (err) {
		const char *errstr = getxinfo_strerr(err);
		fprintf(stderr, "Fatal: getnameinfo(): %s\n", errstr);
	        exit(1);
	}
}


static void ipaddrtostr(const struct sockaddr *sa, socklen_t salen, char *resbuf, size_t reslen, char *port, size_t plen)
{
	xgetnameinfo(sa, salen, resbuf, reslen, port, plen, NI_NUMERICHOST|NI_NUMERICSERV);
}


static void logendpoints(int dest, int origin)
{
	struct sockaddr_storage ss1, ss2;
	int ret;
	char buf1[INET6_ADDRSTRLEN];
	char buf2[INET6_ADDRSTRLEN];

	socklen_t sa1len, sa2len;

	sa1len = sa2len = sizeof(ss1);

	ret = getpeername(origin, (struct sockaddr *) &ss1, &sa1len);
	if (ret == -1) {
		perror("getpeername");
		return;
	}
	ret = getpeername(dest, (struct sockaddr *) &ss2, &sa1len);
	if (ret == -1) {
		perror("getpeername");
		return;
	}
	ipaddrtostr((const struct sockaddr *) &ss1, sa1len, buf1, sizeof(buf1), NULL, 0);
	ipaddrtostr((const struct sockaddr *) &ss2, sa2len, buf2, sizeof(buf2), NULL, 0);

	fprintf(stderr, "Handling connection from %s to %s", buf1, buf2);
	if (tproxy) {
		char port[8];

		sa1len = sizeof(ss1);
		ret = getsockname(origin, (struct sockaddr *) &ss1, &sa1len);
		if (ret) {
			perror("getsockname");
			return;
		}
		ipaddrtostr((const struct sockaddr *) &ss1, sa1len, buf1, sizeof(buf1), port, sizeof(port));
		fprintf(stderr, " (original destination was %s:%s)", buf1, port);
	}
	fputc('\n', stderr);
}


static int sock_listen_tcp(const char * const listenaddr, const char * const port)
{
	int sock;
	struct addrinfo hints = {
		.ai_protocol = IPPROTO_TCP,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_PASSIVE | AI_NUMERICHOST
	};

	hints.ai_family = wanted_pf;

	struct addrinfo *a, *addr;
	int one = 1;

	xgetaddrinfo(listenaddr, port, &hints, &addr);

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
	int sock;
	struct addrinfo hints = {
		.ai_protocol = IPPROTO_TCP,
		.ai_socktype = SOCK_STREAM
	};
	struct addrinfo *a, *addr;

	hints.ai_family = wanted_pf;

	xgetaddrinfo(remoteaddr, port, &hints, &addr);

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
			case 't': tproxy = true; break;
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
	socklen_t salen = sizeof(sa);
	const char *host, *port;

	if (argc < 3)
		die_usage();

	--argc;
	++argv;

	args = parse_args(argc, argv);

	argc -= args;
	argv += args;

	if (argc < 2) /* we need at least 2 more arguments (srcport, hostname) */
		die_usage();

	listensock = sock_listen_tcp(NULL, argv[0]);
	if (listensock < 0)
		return 1;

	if (tproxy) {
		static int one = 1;
		if (setsockopt(listensock, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)))
			perror("setsockopt(IP_TRANSPARENT)");
	}

	while ((remotesock = accept(listensock, &sa, &salen)) < 0)
		perror("accept");

	host = argv[1];
	/* destport given? if no, use srcport */
	port = argv[2] ? argv[2] : argv[0];
	connsock = sock_connect_tcp(host, port);
	if (connsock < 0)
	       return 1;

	do_chroot();
	logendpoints(connsock, remotesock);
	copyfd_io(connsock, remotesock);
	close(connsock);
	close(remotesock);

	return 0;
}

