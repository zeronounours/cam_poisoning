/*
 * A set of functions to ease the management of promiscuous raw sockets
 */

#include <iface.h>

// standard headers
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>

// For network stuff
//#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

// internal imports
#include <logger.h>
#include <utils.h>

/*
 * Init the network structure from the given interface using ioctls
 * If no interface is found, return 0, else return 1
 */
int get_iface_by_name(const char *ifname, struct iface *iface) {
	int fd;
	struct ifreq ifr;
	int i;
	struct in_addr n_addr;

	// open a socket for ioctls
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	// Initialize the name of the interface
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
	ifr.ifr_name[IFNAMSIZ-1] = 0;
	strncpy(iface->ifname, ifname, IFNAMSIZ-1);
	iface->ifname[IFNAMSIZ-1] = 0;
	log_debug("Retrieve information of interface %s\n", iface->ifname);


	/* Get the interface index */
	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		log_warning("Invalid interface name\n");
		return 0;
	}
	iface->ifindex = ifr.ifr_ifindex;
	log_debug("Interface index: %i\n", iface->ifindex);

	/* Get the interface IP */
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		perror("Failed to retrieve interface IP address");
		exit(1);
	}
	ntoha(&((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr, &iface->ip);
	log_debug("Interface IP: %s\n", inet_htoa(iface->ip));

	/* Get the interface mask */
	ifr.ifr_netmask.sa_family = AF_INET;
	if (ioctl(fd, SIOCGIFNETMASK, &ifr) == -1) {
		perror("Failed to retrieve interface netmask");
		exit(1);
	}
	ntoha(&((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr, &iface->mask);
	log_debug("Interface netmask: %s\n", inet_htoa(iface->mask));

	/* Get the interface hardware addr */
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		perror("Failed to retrieve the interface hardware address");
		exit(1);
	}
	for (i=0; i<ETH_ALEN; i++) {
		iface->hwaddr[i] = ifr.ifr_hwaddr.sa_data[i];
	}
	log_debug("Interface hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			iface->hwaddr[0], iface->hwaddr[1], iface->hwaddr[2],
			iface->hwaddr[3], iface->hwaddr[4], iface->hwaddr[5]);

	close(fd);

	return 1;
}

/*
 * This function tries to locate the interface used to send packets to a given
 * IP
 * If no interface is found, return 0, else return 1
 */
int get_iface_by_ip(struct in_addr search_ip, struct iface *iface) {
	struct ifaddrs *addrs, *iap;
	struct in_addr addr, mask;

	log_debug("Try to find interface for IP %s\n", inet_htoa(search_ip));
	// iterate over all interfaces
	getifaddrs(&addrs);
	for (iap = addrs; iap != NULL; iap = iap->ifa_next) {
		if (iap->ifa_addr
				&& (iap->ifa_flags & IFF_UP)
				&& iap->ifa_addr->sa_family == AF_INET) {
			// Only continue with up IPv4 interfaces which have an IP
			ntoha(&((struct sockaddr_in *)iap->ifa_addr)->sin_addr, &addr);
			ntoha(&((struct sockaddr_in *)iap->ifa_netmask)->sin_addr, &mask);
			// Check if the given IP is in the network range of the interface
			if (IN_NETWORK(search_ip, addr, mask)) {
				log_info("Using interface %s\n", iap->ifa_name);
				// delegate to get_iface_by_name
				get_iface_by_name(iap->ifa_name, iface);
				freeifaddrs(addrs);
				return 1;
			}
		}
	}
	log_warning("Cannot find any interface\n");
	freeifaddrs(addrs);
	return 0;
}

/*
 * Create a promiscuous raw socket
 */
int super_socket(struct iface *iface, int type, int protocol) {
	int sock;
	struct sockaddr_ll addr;
	struct ifreq ifr;

	// open a raw socket to handle the ARP injections
	if ((sock = socket(AF_PACKET, type, htons(protocol))) == -1) {
		perror("Cannot open raw socket");
		exit(1);
	}
	// set the socket non blocking
	//fcntl(sock, F_SETFL, O_NONBLOCK);

	// prepare sockaddr_ll for the bind
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(protocol);
	addr.sll_ifindex = iface->ifindex;

	bind(sock, (struct sockaddr *) &addr, sizeof(addr));

	// Switch the interface to promiscuous mode
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface->ifname, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
		perror("Failed to retrieve interface flags");
		exit(1);
	}
	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
		perror("Failed to retrieve interface flags");
		exit(1);
	}

	return sock;
}

