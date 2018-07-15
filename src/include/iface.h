#ifndef IFACE_H
#define IFACE_H

#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>

// this net_if structure is used to track information about a given interface
// It only handles IPv4
struct iface {
	char ifname[IFNAMSIZ];
	int ifindex;
	struct in_addr ip;
	struct in_addr mask;
	unsigned char hwaddr[ETH_ALEN];
};

int get_iface_by_name(const char *ifname, struct iface *iface);
int get_iface_by_ip(struct in_addr search_ip, struct iface *iface);

// to check if an IP is reachable from the interface
// both in_addr and in_addr_t versions
#define IN_INTERFACE(ipa, iface) ( \
	IN_NETWORK_T((ipa).s_addr, (iface).ip.s_addr, (iface).mask.s_addr) \
	)
#define IN_INTERFACE_T(ipa, iface) ( \
	IN_NETWORK_T((ipa), (iface).ip.s_addr, (iface).mask.s_addr) \
	)

// to check if in a network (struct in_addr & in_addr_t versions)
#define IN_NETWORK(ipa, net, mask) ( \
		IN_NETWORK_T((ipa).s_addr, (net).s_addr, (mask).s_addr) \
		)

#define IN_NETWORK_T(ipa, net, mask) ( \
	((ipa) >= FIRST_IP((net), (mask))) \
	&& ((ipa) <= LAST_IP((net), (mask))) \
	)

// Computation of first & last IPs in a network
#define FIRST_IP(ipa, mask) ( ((ipa) & (mask)) + 1 )
#define LAST_IP(ipa, mask) ( ((ipa) | ~(mask)) - 1 )

// Create a promiscuous raw socket
int super_socket(struct iface *iface, int type, int protocol);

#endif /* IFACE_H */
