#ifndef UTILS_H
#define UTILS_H

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/socket.h>

#define STR(x) #x

char *inet_htoa(struct in_addr in);
int inet_atoh(const char *cp, struct in_addr *inp);
void htona(struct in_addr *in, struct in_addr *out);
void ntoha(struct in_addr *in, struct in_addr *out);

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

// an helper to transform a time in ms into a timeval
#define MS_TO_TV(tv, ms) do { \
	(tv).tv_sec = (ms) / 1000; \
	(tv).tv_usec = ((ms) % 1000) * 1000; \
} while(0)

// an helper to retrieve the difference of two timespec into ms
#define TS_DIFF_IN_MS(ts1, ts2) ( \
		((ts1).tv_sec - (ts2).tv_sec) * 1000 \
		+ ((ts1).tv_nsec - (ts2).tv_nsec) / 1000000 \
		)


#define MAX_PKT_SIZE 1500
#define MAX_EVENTS 5
/*
 * helper function to read a socket with a timeout
 * return 0 if everything went right
 * return 1 if the timeout was reached
 * return -1 in case of errors
 *
 * The callback function is call for each packet and is given the response
 * and the socket address
 * If it returns 0, the recvfrom continue
 * else the recvfrom is stopped here
 *
 * args can be used to share a structure/a variable with the callback
 */
int recvfrom_with_timeout(int sock, const int timeout,
		int (*callback)(void *buf, ssize_t buflen,
			struct sockaddr *addr, socklen_t addr_l, void *args),
		void *args);
int recvfrom_multiple_with_timeout(int epollfd, const int timeout,
		int (*callback)(void *buf, ssize_t buflen,
			struct sockaddr *addr, socklen_t addr_l, void *args),
		void *args);

#endif /* UTILS_H */
