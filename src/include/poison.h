#ifndef POISON_H
#define POISON_H

#include <stdint.h>

#include <netinet/in.h>
#include <net/ethernet.h>

#include <sys/time.h>

#include <ipc.h>
#include <iface.h>


struct message {
	size_t len;
	void *buf;
};

#define QLIST_MAX_SIZE 128
struct qlist {
	uint8_t dest[ETH_ALEN];
	uint8_t count;
	struct message messages[QLIST_MAX_SIZE];
};

#define QUEUE_INIT_SIZE 256
struct queue {
	size_t count;
	size_t size;
	struct qlist *entries;
};

/* the following inline functions are defined inside poison.c
int inline init_queue(struct queue *q);
struct qlist inline *queue_get_entry(struct queue *q,uint8_t sender[ETH_ALEN]);
int inline queue_message(struct queue *q, void *buf, size_t buflen);
int inline free_queue(struct queue *q);
*/

// structure for callback arg
struct cb_args {
	struct queue *queue;
	union {
		struct in_addr *ip;
		struct {
			uint8_t *h1;
			uint8_t *h2;
			uint8_t *local;
			struct ipc *ipc;
		};
	};
};

#define ARP_RESTORE_TIMEOUT 250			// in ms
#define ARP_RESTORE_MAX_RETRY 3
// launch attacks relies on inline function. The following callbacks are used
// by these
int receive_messages_callback(void *buf, ssize_t buflen,
		struct sockaddr *addr, socklen_t addr_l, void *args);
int restore_mac_callback(void *buf, ssize_t buflen,
		struct sockaddr *addr, socklen_t addr_l, void *args);


void launch_attack(struct iface *iface, struct ipc *ipc, int freq,
		struct in_addr h1, struct in_addr h2);

#endif /* POISON_H */
