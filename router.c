#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "list.h"
#include "trie.h"

#define ARP_TYPE htons(0x0806)
#define IP_TYPE htons(0x0800)
#define DESTINATION_UNREACHABLE 0
#define TIME_EXCEEDED 1

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_entry *mac_table;
int mac_table_len;

/* Queue element structure: just as the forum said - kept the buffer itself and its length */
struct que_elem {
	int cur_len;
	char packk[MAX_PACKET_LEN];
};

/* global queue and the number of packets in it */
queue Q;
int q_len = 0;

/* global trie root */
struct trie_node *root;

/* using an ip address, go down bit by bit. We might find more suitable entries,
 * but we keep in ret the lowest (most recent) one found
 */
struct route_table_entry *find_LPM(uint32_t ip_address) {
    struct route_table_entry *ret = NULL;
    struct trie_node *save = root;
    while (save != NULL) {
        if (save->is_leaf == 1) {
            ret = save->route_entry;
        }
        if ((ip_address & 1) == 1) {
            save = save->right;
        } else {
            save = save->left;
        }
		ip_address = ip_address >> 1;
    }
    return ret;   
}

/* iterate through a mask until we find the first 0. The mask is in network order */
int get_mask_length(uint32_t mask)
{
    int l = 0;
    for (int i = 0; i < 32; i++) {
        if ((mask & 1) == 1)
            l++;
        else
            return l;
        mask = mask >> 1;
    }
    return l;
}

/* return a pointer to the the arp/mac table entry afferent to an ip address
 * return NULL if the entry doesn't exist yet
 */
struct arp_entry *get_mac_entry(uint32_t ip_dest) 
{
	for (int i = 0; i < mac_table_len; i++) {
		if (mac_table[i].ip == ip_dest) {
			return &(mac_table[i]);
		}
	}
	return NULL;
}

/* build an IPv4 packet by copying the info from the afferent headers - Ethernet, IP and payload */
void fill_packet(char *packet, struct iphdr *ip_hdr, struct ether_header *eth_hdr, char *buf, int len) {
	memcpy(packet, eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), buf + sizeof(struct ether_header) + sizeof(struct iphdr),
			len - (sizeof(struct ether_header) + sizeof(struct iphdr)));
}

/* build and send an icmp packet for TIME_EXCEEDED and DESTINATION UNREACHABLE */
void send_icmp(int interface, size_t len, struct ether_header *eth_hdr, struct iphdr *ip_hdr, char *buf, short errr) {
	char packet[MAX_PACKET_LEN];

	/* build initial eth & ip header */
	uint32_t save_addr = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = save_addr;
	ip_hdr->ttl = 100;
	ip_hdr->protocol = 1;
	ip_hdr->tot_len = htons(sizeof(struct icmphdr) + 2 * sizeof(struct iphdr) + 8);
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	/* get where to send */
	struct route_table_entry *rt = find_LPM(ip_hdr->daddr);

	struct arp_entry *m = malloc(sizeof(struct arp_entry));
	m = get_mac_entry(rt->next_hop);
	uint8_t *macc = calloc(6, sizeof(uint8_t));
	get_interface_mac(rt->interface, macc);

	/* build Ethernet header */
	memcpy((char *)eth_hdr->ether_shost, (char *)macc, 6 * sizeof(uint8_t));
	memcpy((char *)eth_hdr->ether_dhost, (char *) (m->mac), 6 * sizeof(uint8_t));


	/* build icmp header */
	struct icmphdr *icm = malloc(sizeof(struct icmphdr));
	icm->code = 0;
	switch (errr)
	{
		case DESTINATION_UNREACHABLE:
			icm->type = 3;
			break;
		
		case TIME_EXCEEDED:
			icm->type = 11;
			break;

		default:
			icm->type = 0;
			break;
	}
	icm->checksum = 0;
	icm->un.echo.id = 0;
	icm->un.echo.sequence = 0;
	
	char icmp_part[MAX_PACKET_LEN];
	memcpy(icmp_part, icm, sizeof(struct icmphdr));
	/* add the ip header + 64 bits (8 bytes)*/
	memcpy(icmp_part + sizeof(struct icmphdr), buf + sizeof(struct ether_header), sizeof(struct iphdr) + 8);
	icm->checksum = htons(checksum((uint16_t *) icmp_part, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

	/* build packet: Ethernet + IPv4 + ICMP header + IPv4 again + 64 bits */
	memcpy(packet, eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), icm, sizeof(struct icmphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
		icmp_part + sizeof(struct icmphdr), sizeof(struct iphdr) + 8);

	/* send the icmp packet */
	send_to_link(rt->interface, packet, sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
}

/* Echo reply: Basically send the received message back to the sender with the types changed */
void icmp_reply(int interface, size_t len, char *buf) {

	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	/* basically switch the sender and receiver */
	uint32_t save_addr = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = save_addr;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	/* build Ethernet header */
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct route_table_entry *rt = find_LPM(ip_hdr->daddr);

	struct arp_entry *m = malloc(sizeof(struct arp_entry));
	m = get_mac_entry(rt->next_hop);
	uint8_t *macc = calloc(6, sizeof(uint8_t));
	get_interface_mac(rt->interface, macc);

	memcpy((char *)eth_hdr->ether_shost, (char *)macc, 6 * sizeof(uint8_t));
	memcpy((char *)eth_hdr->ether_dhost, (char *) (m->mac), 6 * sizeof(uint8_t));

	/* All the modifications: change the code and type */
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->code = 0;
	icmp_hdr->type = 0;

	/* send the packet */
	send_to_link(rt->interface, buf, len);
}

/* we get an arp request and we need to send back an arp reply with our data in it */
void generate_arp_reply(struct arp_header *arp_received, struct ether_header *eth_hdr, struct sockaddr_in sa) 
{
	char arp_reply_packet[MAX_PACKET_LEN];

	struct route_table_entry *rt = find_LPM(arp_received->spa);
	/* Ethernet header */
	struct ether_header *eth_arp = malloc(sizeof(struct ether_header));
	uint8_t *mac_to_next_hop = calloc(6, sizeof(uint8_t));
	get_interface_mac(rt->interface, mac_to_next_hop);
	memcpy((char *)eth_arp->ether_shost, (char *) mac_to_next_hop, 6 * sizeof(uint8_t));

	memcpy((char *)eth_arp->ether_dhost, (char *) eth_hdr->ether_shost, 6 * sizeof(uint8_t));
	eth_arp->ether_type = ARP_TYPE;

	/* Arp Header */
	struct arp_header *arp_arp = malloc(sizeof(struct arp_header));
	arp_arp->htype = htons(1);
	arp_arp->ptype = IP_TYPE;
	arp_arp->hlen = 6;
	arp_arp->plen = 4;
	arp_arp->op = htons(2);
	memcpy(arp_arp->sha, mac_to_next_hop, 6 * sizeof(uint8_t));
	inet_pton(AF_INET, get_interface_ip(rt->interface), &(sa.sin_addr));
	arp_arp->spa = sa.sin_addr.s_addr;

	memcpy(arp_arp->tha, (char *) eth_hdr->ether_shost, 6 * sizeof(uint8_t));
	arp_arp->tpa = rt->next_hop;

	/* build the packet with the Ethernet and Arp Headers */
	memcpy(arp_reply_packet, eth_arp, sizeof(struct ether_header));
	memcpy(arp_reply_packet + sizeof(struct ether_header), arp_arp, sizeof(struct arp_header));
	send_to_link(rt->interface, arp_reply_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
}

/* See what packets we can send with the newly obtained info */
void iterate_through_queue() {
	int new_q_len = 0;
	/* go through all elements in queue exactly once */
	for (int i = 0; i < q_len; i++) {
		struct que_elem* element = queue_deq(Q);
		
		/* build the ip  */
		struct iphdr *ip_h = (struct iphdr *) (element->packk + sizeof(struct ether_header));
		struct ether_header *eth_h = (struct ether_header *) element->packk;
		struct route_table_entry *rt = find_LPM(ip_h->daddr);
		struct arp_entry *m;
		m = get_mac_entry(rt->next_hop);

		if (m == NULL) {
			/* we haven't got the entry yet, put back to the queue */
			new_q_len++;
			queue_enq(Q, element);
		} else {
			/* now we have the physical address, we can send the packet */
			uint8_t *macc = calloc(6, sizeof(uint8_t));
			get_interface_mac(rt->interface, macc);

			memcpy((char *)eth_h->ether_shost, (char *)macc, 6 * sizeof(uint8_t));
			memcpy((char *)eth_h->ether_dhost, (char *) (m->mac), 6 * sizeof(uint8_t));

			/* create new packet */
			char packet[MAX_PACKET_LEN];
			fill_packet(packet, ip_h, eth_h, element->packk, element->cur_len);

			send_to_link(rt->interface, element->packk, element->cur_len);
		}
	}
	/* update the current length with the number of still unsent packets */
	q_len = new_q_len;
}

/* Build an arp request packet with a broadcast mac address */
void generate_arp_request(struct route_table_entry *rt, struct sockaddr_in sa)
{
	char arp_req_packet[MAX_PACKET_LEN];

	/* Ethernet header */
	struct ether_header *eth_arp = malloc(sizeof(struct ether_header));
	uint8_t *mac_to_next_hop = calloc(6, sizeof(uint8_t));
	get_interface_mac(rt->interface, mac_to_next_hop);
	memcpy((char *)eth_arp->ether_shost, (char *) mac_to_next_hop, 6 * sizeof(uint8_t));

	/* put broadcast address */
	uint8_t *broadcast_mac = calloc(6, sizeof(uint8_t));
	hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast_mac);
	memcpy((char *)eth_arp->ether_dhost, (char *) broadcast_mac, 6 * sizeof(uint8_t));

	eth_arp->ether_type = ARP_TYPE;

	/* ARP Header */
	struct arp_header *arp_arp = malloc(sizeof(struct arp_header));
	arp_arp->htype = htons(1);
	arp_arp->ptype = IP_TYPE;
	arp_arp->hlen = 6;
	arp_arp->plen = 4;
	arp_arp->op = htons(1);
	memcpy(arp_arp->sha, mac_to_next_hop, 6 * sizeof(uint8_t));
	inet_pton(AF_INET, get_interface_ip(rt->interface), &(sa.sin_addr));
	arp_arp->spa = sa.sin_addr.s_addr;

	uint8_t *just_sum_mac = calloc(6, sizeof(uint8_t));
	memcpy(arp_arp->tha, just_sum_mac, 6 * sizeof(uint8_t));
	arp_arp->tpa = rt->next_hop;

	/* build and send the packet */
	memcpy(arp_req_packet, eth_arp, sizeof(struct ether_header));
	memcpy(arp_req_packet + sizeof(struct ether_header), arp_arp, sizeof(struct arp_header));
	send_to_link(rt->interface, arp_req_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	Q = queue_create();

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* allocate route table */
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "rtable malloc");
	rtable_len = read_rtable(argv[1], rtable);

	/* populate the trie with the route table entries put at the right depth */
	root = create_node(NULL);
	for (int i = 0; i < rtable_len; i++) {
        root = insert_node(root, &(rtable[i]), rtable[i].prefix, get_mask_length(rtable[i].mask));
    }

	mac_table = malloc(sizeof(struct arp_entry) * 100);
	DIE(mac_table == NULL, "mac_table malloc");
	mac_table_len = 0;

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		/* get the ip address of the interface on which we received data */
		struct sockaddr_in sa;
		inet_pton(AF_INET, get_interface_ip(interface), &(sa.sin_addr));

		/* check whether it is arp type */
		if (eth_hdr->ether_type == ARP_TYPE) {
			struct arp_header *arp_received = (struct arp_header *) (buf + sizeof(struct ether_header));
			/* if address request */
			if (ntohs(arp_received->op) == 1 && sa.sin_addr.s_addr == arp_received->tpa) {

				/* add to mac table */
				memcpy(mac_table[mac_table_len].mac, arp_received->sha, 6 * sizeof(uint8_t));
				mac_table[mac_table_len++].ip = arp_received->spa;

				/* generate arp reply */
				generate_arp_reply(arp_received, eth_hdr, sa);
				continue;

			} else if (ntohs(arp_received->op) == 2 && sa.sin_addr.s_addr == arp_received->tpa) {
				/* if we got a reply
				 * add to mac table 
				 */
				memcpy(mac_table[mac_table_len].mac, arp_received->sha, 6 * sizeof(uint8_t));
				mac_table[mac_table_len++].ip = arp_received->spa;

				/* iterate through queue */
				iterate_through_queue();
				continue;
			}
		}

		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		/* checksum */
		uint16_t save_check = ip_hdr->check;
		ip_hdr->check = 0;
		if (ntohs(save_check) != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
			continue;
		}

		/* check if a request was headed to us */
		if (sa.sin_addr.s_addr == ip_hdr->daddr) {
			icmp_reply(interface, len, buf);
			continue;
		}

		/* check TTL and recalculate checksum */
		if (ip_hdr->ttl <= 1) {
			ip_hdr->check = save_check;
			send_icmp(interface, len, eth_hdr, ip_hdr, buf, TIME_EXCEEDED);
			continue;
		}
		ip_hdr->ttl--;
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		/* get the entry with LPM */
		struct route_table_entry *rt = find_LPM(ip_hdr->daddr);
		if (rt == NULL) {
			send_icmp(interface, len, eth_hdr, ip_hdr, buf, DESTINATION_UNREACHABLE);
			continue;
		}

		/* update ethernet addresses */
		struct arp_entry *m;
		m = get_mac_entry(rt->next_hop);

		if (m != NULL) {
			/* found entry in arp table */
			uint8_t *macc = calloc(6, sizeof(uint8_t));
			get_interface_mac(rt->interface, macc);

			memcpy((char *)eth_hdr->ether_shost, (char *)macc, 6 * sizeof(uint8_t));
			memcpy((char *)eth_hdr->ether_dhost, (char *) (m->mac), 6 * sizeof(uint8_t));

			/* create new packet */
			char packet[MAX_PACKET_LEN];
			fill_packet(packet, ip_hdr, eth_hdr, buf, len);
			send_to_link(rt->interface, packet, len);
		} else {
			/* mac table entry non-existent, add element to queue and make an arp request */
			struct que_elem* element = malloc(sizeof(struct que_elem));
			element->cur_len = len;
			memcpy(element->packk, buf, len);

			queue_enq(Q, element);
			q_len++;
			generate_arp_request(rt, sa);
			continue;
		}
	}
}
