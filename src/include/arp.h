#ifndef ARP_H
#define ARP_H

#include <stdint.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <iface.h>

#define ETHER_CMP(a,b) \
	((a)[0] == (b)[0]) && \
	((a)[1] == (b)[1]) && \
	((a)[2] == (b)[2]) && \
	((a)[3] == (b)[3]) && \
	((a)[4] == (b)[4]) && \
	((a)[5] == (b)[5])

// Local ARP cache
struct arp_entry {
	unsigned char hrd_addr[ETH_ALEN];
	struct in_addr pro_addr;
};

#define ARP_CACHE_INIT_SIZE 1024
struct {
	struct arp_entry *entries;
	size_t count;
	size_t size;
} arp_cache;

void arp_cache_init(void);
void arp_cache_add(uint8_t hrd[ETH_ALEN], in_addr_t pro);
struct in_addr *arp_cache_search_ip(uint8_t hrd[ETH_ALEN]);
uint8_t *arp_cache_search_mac(struct in_addr ip);
void arp_cache_free(void);

// ARP packets
struct arp_pkt {
	struct ether_header	eh;
	struct ether_arp	ah;
} __attribute__((packed));

int arp_request_base(void *buf, size_t buflen);
// To create an ARP request to learn the mac of the given IP
int arp_request(struct iface *iface, in_addr_t ip, void *buf, size_t buflen);
// To create an ARP request with the given MAC address
int arp_poison(struct iface *iface,
		uint8_t mac[ETH_ALEN], void *buf, size_t buflen);

// ARP scanner
#define ARP_SCANNER_PARALLEL 128
#define ARP_SCANNER_TIMEOUT 250			// in ms
#define ARP_SCANNER_FINAL_TIMEOUT 1000	// in ms
size_t arp_scan(struct iface *iface);

#define ARP_ENSURE_TIMEOUT 150			// in ms
#define ARP_ENSURE_MAX_RETRY 5
int arp_ensure(struct iface *iface, struct in_addr ip);

/*
 * This callback is to be given to recvfrom_with_timeout, and is used by both
 * arp_ensure() and arp_scan().
 *
 * If args is not NULL, it should be a pointer to a struct in_addr. If the
 * response match the address, the callback stop recvfrom
 *
 */
int arp_update_cache_callback(void *buf, ssize_t buflen,
		struct sockaddr *addr, socklen_t addr_l, void *args);
#endif /* ARP_H */
