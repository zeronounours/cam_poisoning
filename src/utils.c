
#include <utils.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <sys/epoll.h>
#include <arpa/inet.h>

#include <logger.h>

// Similar to inet_ntoa but with host endiannes as input
char *inet_htoa(struct in_addr in) {
	struct in_addr n;
	n.s_addr = htonl(in.s_addr);
	return inet_ntoa(n);
}

// Similar to inet_aton but with host endiannes as output
int inet_atoh(const char *cp, struct in_addr *inp) {
	struct in_addr n;
	int ret;
	ret = inet_aton(cp, &n);
	inp->s_addr = ntohl(n.s_addr);
	return ret;
}

void htona(struct in_addr *in, struct in_addr *out) {
	out->s_addr = htonl(in->s_addr);
}

void ntoha(struct in_addr *in, struct in_addr *out) {
	out->s_addr = ntohl(in->s_addr);
}

// Helpers to make recvfrom calls with timeouts
int recvfrom_with_timeout(int sock, const int timeout,
		int (*callback)(void *buf, ssize_t buflen,
			struct sockaddr *addr, socklen_t addr_l, void *args),
		void *args) {

	int ret;
	// create the epoll with only one fd and delegate to
	// recvfrom_multiple_with_timeout
	struct epoll_event ev;
	int epollfd = epoll_create1(0);
	if (epollfd == -1) {
		perror("Failed to create the epoll");
		return -1;
	}

	// Add the event to the structure
	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &ev) == -1) {
		perror("Failed to add the socket to the epoll");
		return -1;
	}

	// do the delegation
	ret = recvfrom_multiple_with_timeout(epollfd, timeout, callback, args);

	// clear the epoll
	if (epoll_ctl(epollfd, EPOLL_CTL_DEL, sock, &ev) == -1) {
		perror("Failed to remove the socket to the epoll");
		return -1;
	}
	close(epollfd);

	// return the same result as recvfrom_multiple_with_timeout
	return ret;
}

int recvfrom_multiple_with_timeout(int epollfd, const int timeout,
		int (*callback)(void *buf, ssize_t buflen,
			struct sockaddr *addr, socklen_t addr_l, void *args),
		void *args) {

	uint8_t res[MAX_PKT_SIZE];
	ssize_t res_l;
	struct sockaddr addr = {0};
	socklen_t addr_l = sizeof(addr);

	struct timespec current_t, start_t;
	int remaining_t;

	struct epoll_event events[MAX_EVENTS];
	int nfds, i;

	// retrieve the current time
	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &start_t) == -1) {
		perror("Failed to get the initial clock time");
		return -1;
	}
	remaining_t = timeout;

	log_debug("Receiving messages for %ims\n", timeout);

	// read response when available
	while (1) {
		// poll all given fd
		nfds = epoll_wait(epollfd, events, MAX_EVENTS, timeout);

		// handle case of timeout & errors
		if (nfds == -1) {
			perror("Error while polling sockets");
			return -1;
		} else if (nfds == 0) {
			// timeout
			return 0;
		}

		// read all available fd
		for (i=0; i<nfds; i++) {
			res_l = recvfrom(events[i].data.fd,
					&res, sizeof(res), 0, &addr, &addr_l);

			// handle errors
			if (res_l == -1) {
				perror("Error while reading sockets");
				return -1;
			}

			// delegate to the callback
			if (callback(&res, res_l, &addr, addr_l, args)) {
				// the callback return something different to 0, stop here
				log_debug("Receive loop interrupted\n");
				return 1;
			}
		}

		// Compute the remaining time for the timeout
		if (clock_gettime(CLOCK_MONOTONIC_COARSE, &current_t) == -1) {
			perror("Failed to get the current clock time");
			return -1;
		}
		remaining_t = timeout - TS_DIFF_IN_MS(current_t, start_t);
		if (remaining_t < 0)
			remaining_t = 0;

	}
	// never reached
}
