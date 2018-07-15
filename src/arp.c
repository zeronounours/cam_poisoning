
/*
 * To restore the CAM tables, we use ARP to force remote devices to send a
 * frame. We then need their IP address to send the who-has request.
 */

#include <arp.h>

// standard headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

// for sockets
#include <sys/socket.h>
#include <sys/time.h>

// network headers
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

// additional in-application headers
#include <logger.h>
#include <iface.h>
#include <utils.h>


/*
 * ARP Cache management
 */
void arp_cache_init() {
	arp_cache.entries = (struct arp_entry*) malloc(
			ARP_CACHE_INIT_SIZE * sizeof(struct arp_entry)
			);
	if (arp_cache.entries == NULL) {
		perror("Cannot allocate memory for the ARP cache");
		exit(1);
	}
	arp_cache.count = 0;
	arp_cache.size = ARP_CACHE_INIT_SIZE;
	log_debug("ARP cache initialized\n");
}

void arp_cache_add(uint8_t hrd[ETH_ALEN], in_addr_t pro) {
	int i;
	struct arp_entry *cur_entry;
	struct arp_entry *entries;

	if (arp_cache.size == 0) {
		// initialize the cache if not done before
		arp_cache_init();
	} else if (arp_cache.count == arp_cache.size) {
		// increase the size of the cache if needed
		entries = (struct arp_entry*) realloc(arp_cache.entries,
				2 * arp_cache.size * sizeof(struct arp_entry)
				);
		if (entries == NULL) {
			log_warning("Cannot reallocate memory to extend ARP cache\n");
			return;
		}
		arp_cache.entries = entries;
		arp_cache.size *= 2;
	}

	cur_entry = &arp_cache.entries[arp_cache.count++];

	for (i=0; i<ETH_ALEN; i++)
		cur_entry->hrd_addr[i] = hrd[i];
	cur_entry->pro_addr.s_addr = pro;

	log_info("ARP Cache updated: %-16s is at %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_htoa(cur_entry->pro_addr),
			cur_entry->hrd_addr[0], cur_entry->hrd_addr[1],
			cur_entry->hrd_addr[2], cur_entry->hrd_addr[3],
			cur_entry->hrd_addr[4], cur_entry->hrd_addr[5]);
}

struct in_addr *arp_cache_search_ip(uint8_t hrd[ETH_ALEN]) {
	size_t i;
	for (i=0; i<arp_cache.count; i++) {
		if (ETHER_CMP(arp_cache.entries[i].hrd_addr, hrd)) {
			log_debug("ARP cache search: "
					"%02x:%02x:%02x:%02x:%02x:%02x found at %s\n",
					hrd[0], hrd[1], hrd[2], hrd[3], hrd[4], hrd[5],
					inet_htoa(arp_cache.entries[i].pro_addr));
			return &arp_cache.entries[i].pro_addr;
		}
	}
	log_debug("ARP cache search: not found\n");
	return NULL;
}

uint8_t *arp_cache_search_mac(struct in_addr ip) {
	size_t i;
	for (i=0; i<arp_cache.count; i++) {
		if (arp_cache.entries[i].pro_addr.s_addr == ip.s_addr) {
			log_debug("ARP cache search: "
					"%s found at %02x:%02x:%02x:%02x:%02x:%02x\n",
					inet_htoa(ip),
					arp_cache.entries[i].hrd_addr[0],
					arp_cache.entries[i].hrd_addr[1],
					arp_cache.entries[i].hrd_addr[2],
					arp_cache.entries[i].hrd_addr[3],
					arp_cache.entries[i].hrd_addr[4],
					arp_cache.entries[i].hrd_addr[5]
					);
			return (uint8_t *) &arp_cache.entries[i].hrd_addr;
		}
	}
	log_debug("ARP cache search: not found\n");
	return NULL;
}

void arp_cache_free(void) {
	free(arp_cache.entries);
	arp_cache.count = 0;
	arp_cache.size = 0;
	log_debug("ARP cache freed\n");
}

/*
 * ARP packets
 */

/*
 * Create an ARP request in buf
 * Return the size of the packet
 */
int arp_request_base(void *buf, size_t buflen) {
	struct arp_pkt *arp;

	// First check the buffer is long enough
	if (buflen < sizeof(struct arp_pkt)) {
		log_warning("Try to create an ARP request with a too-small buffer\n");
		return 0;
	}

	// Set the protocol header pointers
	arp = (struct arp_pkt *) buf;

	// set ethernet fields
	arp->eh.ether_type = htons(ETHERTYPE_ARP);

	// set ARP fields
	arp->ah.arp_hrd = htons(ARPHRD_ETHER);
	arp->ah.arp_pro = htons(ETHERTYPE_IP);
	arp->ah.arp_hln = ETH_ALEN;
	arp->ah.arp_pln = 4;
	arp->ah.arp_op = htons(ARPOP_REQUEST);

	// destination MAC address
	memset(arp->eh.ether_dhost, 0xff, ETH_ALEN);
	memset(arp->ah.arp_tha, 0, ETH_ALEN);

	return sizeof(struct arp_pkt);
}

int arp_request(struct iface *iface, in_addr_t ip, void *buf, size_t buflen) {
	struct arp_pkt *arp;
	in_addr_t *ipp;
	int ret;

	// Set the protocol header pointers
	arp = (struct arp_pkt *) buf;

	// Get the base ARP request
	ret = arp_request_base(buf, buflen);

	// source MAC address to the local MAC address
	memcpy(arp->eh.ether_shost, iface->hwaddr, ETH_ALEN);
	memcpy(arp->ah.arp_sha, iface->hwaddr, ETH_ALEN);

	// set the IP requested IP and the source IP
	ipp = (in_addr_t *)arp->ah.arp_spa;
	*ipp = htonl(iface->ip.s_addr);
	ipp = (in_addr_t *)arp->ah.arp_tpa;
	*ipp = htonl(ip);

	// Debug ARP print
	/*log_debug("Crafted an ARP request:\n");
	log_pkt_debug(buf, buflen);*/

	return ret;
}

int arp_poison(struct iface *iface, uint8_t mac[ETH_ALEN],
		void *buf, size_t buflen) {
	struct arp_pkt *arp;
	in_addr_t *ipp;
	int ret;

	// Set the protocol header pointers
	arp = (struct arp_pkt *) buf;

	// Get the base ARP request
	ret = arp_request_base(buf, buflen);

	// source MAC address to the poisoned MAC address
	memcpy(arp->eh.ether_shost, mac, ETH_ALEN);
	memcpy(arp->ah.arp_sha, mac, ETH_ALEN);

	// set the IP requested IP to the localhost and the source IP to the
	// poisoned device's one
	ipp = (in_addr_t *)arp->ah.arp_spa;
	*ipp = htonl(arp_cache_search_ip(mac)->s_addr);
	ipp = (in_addr_t *)arp->ah.arp_tpa;
	*ipp = htonl(iface->ip.s_addr);

	// Debug ARP print
	/*log_debug("Crafted an ARP request:\n");
	log_pkt_debug(buf, buflen);*/

	return ret;
}

/*
 * The ARP scanner scans the whole interface network and update its local ARP
 * cache.
 * Return the number of found hosts
 */
size_t arp_scan(struct iface *iface) {
	// commons
	int i;

	// for scanner loop
	in_addr_t cur_ip, first, last;
	int timeout;

	// socket
	int sock;

	// buffers for ARP
	struct arp_pkt req;
	in_addr_t *ah_ip_req = (in_addr_t *) &req.ah.arp_tpa;

	log_debug("Launching the ARP scan\n");

	// open a promiscuous raw socket (error are handle by super_socket)
	sock  = super_socket(iface, SOCK_RAW, ETH_P_ARP);

	// Create the base arp request
	if (!arp_request(iface, 0, &req, sizeof(req))) {
		log_error("Failed to craft an ARP request\n");
		close(sock);
		return 0;
	}

	// Prepare the loops
	timeout = ARP_SCANNER_TIMEOUT;

	first = FIRST_IP(iface->ip.s_addr, iface->mask.s_addr);
	last = LAST_IP(iface->ip.s_addr, iface->mask.s_addr);

	// loop to send and receive all ARP requests
	// Double loop to limit the number of parallel requests
	log_debug("Start sending ARP requests\n");
	for (cur_ip = first; cur_ip <= last;) {
		for (i = 0; i < ARP_SCANNER_PARALLEL && cur_ip <= last; i++,cur_ip++) {
			// Send the ARP for the current IP
			*ah_ip_req = htonl(cur_ip);
			if (send(sock, &req, sizeof(req), 0) == -1) {
				perror("Error while sending ARP");
				exit(1);
			}
		}

		// for the final batch increase the timeout
		if (cur_ip > last) {
			timeout = ARP_SCANNER_FINAL_TIMEOUT;
		}

		// read responses
		switch (recvfrom_with_timeout(sock, timeout,
					&arp_update_cache_callback, NULL)) {
			case -1:
				// error
				exit(1);
			case 0:
				// timeout
			default:
				// recvfrom found the right packet
				continue;	// next set of requests
		}
	}

	// close the socket
	close(sock);

	return arp_cache.count;
}
/*
 * Function to ensure an IP is found in the ARP cache
 */
int arp_ensure(struct iface *iface, struct in_addr ip) {
	int i;
	int sock;
	struct timeval tv;
	struct arp_pkt req, res;
	struct sockaddr_ll addr = {0};
	socklen_t addrlen = sizeof(addr);

	log_info("Ensure host %s is in the local ARP cache\n", inet_htoa(ip));

	// Check the local cache
	if (arp_cache_search_mac(ip) != NULL) {
		log_debug("Host is already in the local cache\n");
		return 1;
	}

	// open a promiscuous raw socket (error are handle by super_socket)
	sock  = super_socket(iface, SOCK_RAW, ETH_P_ARP);

	// Create the base arp request
	if (!arp_request(iface, ip.s_addr, &req, sizeof(req))) {
		log_error("Failed to craft an ARP request\n");
		close(sock);
		return 0;
	}

	log_debug("Not found in cache: start sending ARP requests\n");
	for (i=0; i<ARP_ENSURE_MAX_RETRY; i++) {
		log_debug("ARP Ensure: sending packet #%i\n", i+1);
		if (send(sock, &req, sizeof(req), 0) == -1) {
			perror("Error while sending ARP");
			exit(1);
		}

		// read responses
		switch (recvfrom_with_timeout(sock, ARP_ENSURE_TIMEOUT,
					&arp_update_cache_callback, &ip)) {
			case -1:
				// error
				exit(1);
			case 0:
				// timeout
				continue;	// Retry ARP request
			default:
				// recvfrom found the right packet
				close(sock);
				return 1;		// stop here with success status
		}
	}

	// close the socket
	close(sock);
	return 0;
}

// recvfrom_with_timeout callback to handle all ARP
int arp_update_cache_callback(void *buf, ssize_t buflen,
		struct sockaddr *addr, socklen_t addr_l, void *args) {

	// cast to arp packet
	struct arp_pkt *res = (struct arp_pkt *)buf;
	struct sockaddr_ll *recvaddr = (struct sockaddr_ll *)addr;

	// read it and update cache
	// sanity checks on the frame
	if (recvaddr->sll_pkttype != PACKET_OUTGOING &&
			res->eh.ether_type == htons(ETHERTYPE_ARP) &&
			res->ah.arp_hrd == htons(ARPHRD_ETHER) &&
			res->ah.arp_pro == htons(ETHERTYPE_IP) &&
			res->ah.arp_op == htons(ARPOP_REPLY)) {

		// update the cache
		arp_cache_add(
				res->ah.arp_sha,	// hwaddr
				ntohl(*(in_addr_t *)res->ah.arp_spa));	// ipaddr

		// Check the stop condition
		if (args != NULL &&
				((struct in_addr *)args)->s_addr ==
				ntohl(*(in_addr_t *)res->ah.arp_spa)) {
			return 1;	// stop the recvfrom loop
		}
	}
	return 0;	// continue the recvfrom loop
}

