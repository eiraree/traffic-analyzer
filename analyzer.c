#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>

int main () {
ssize_t rec = 0;
char * buff = NULL;
int sock = -1;
int i = 0;

/* structure align */
/* выравнивание элементов структуры */
struct ether_header {
	char dest_mac [6];
	char src_mac [6];
	short eth_type;
} __attribute__((__packed__));

struct ipv4_header {
	unsigned header_size : 4;
	unsigned version : 4;
	unsigned dscp : 6;
	unsigned ecn : 2;
	short packet_size; 
	short identificator;
	unsigned flags : 3;
	unsigned fragment_offset : 13;
	char time_to_live;
	char protocol;
	short header_checksum;
	int ip_source;
	int ip_dest;
	int options;
}__attribute__((__packed__)); 

struct types_array {
	unsigned short type;
	char * string;
};

struct types_array table_of_types [] = {
	{0x0800, "IPv4"},
	{0x0806, "ARP"},
	{0x8137, "IPX"},
	{0x888E, "EAP"},
};


struct ether_header * data_packet; 
struct ipv4_header * data_ipv4;

if ((sock = socket (AF_PACKET, SOCK_RAW, ETH_P_ALL)) < 0) {
	printf("ERROR! %s\n", strerror(errno));	
	return 1;	
}

struct sockaddr_ll sll;

struct in_addr ip_source_struct;
struct in_addr ip_dest_struct;

sll.sll_family = AF_PACKET;
sll.sll_protocol = htons(ETH_P_ALL);
sll.sll_ifindex = 0;

if (bind (sock, (struct sockaddr *) &sll, sizeof (sll)) == -1) {
	printf ("ERROR! %s\n", strerror(errno));
	return 1;
}

buff = (char*) malloc (ETH_FRAME_LEN); 

while (1) {
	rec = recvfrom (sock, buff, ETH_FRAME_LEN, 0, NULL, 0);
	if (rec == -1)
		return -1;

	data_packet = (struct ether_header *) buff;
	data_ipv4 = (struct ipv4_header *) &buff[14];

	printf ("Packet size: %ld \n", rec);
	
	printf ("Destination MAC: ");
	for (i = 0; i < 6; i++){
		printf ("%.2hhX ", data_packet->dest_mac[i]);
	}
	printf ("\n");

	
	printf ("Source MAC: ");
	for (i = 0; i < 6; i++) {
		printf ("%.2hhX ", data_packet->src_mac[i]);
	}
	printf ("\n");


	for (i = 0; i < 4; i++) {
		if (table_of_types[i].type ==  ntohs(data_packet->eth_type)) {
		printf ("EtherType: %#.4x is %s\n", ntohs(data_packet->eth_type), table_of_types[i].string);
		break;
		}
	}

	if (ntohs(data_packet->eth_type) == 0x0800) {

		ip_source_struct.s_addr = data_ipv4->ip_source;
		ip_dest_struct.s_addr = data_ipv4->ip_dest;

		printf ("Version: %hhu \n", data_ipv4->version);
		printf ("Header size: %hhu \n", data_ipv4->header_size);
		printf ("DCSP: %u \n", data_ipv4->dscp);
		printf ("ECN: %u \n", data_ipv4->ecn);
		printf ("Packet size: %hu \n", data_ipv4->packet_size);
		printf ("Identificator: %hu \n", data_ipv4->identificator);
		printf ("Flags: %u \n", data_ipv4->flags);
		printf ("Fragment offset: %u \n", data_ipv4->fragment_offset);
		printf ("Time to live: %hhu \n", data_ipv4->time_to_live);
		printf ("Protocol: %hhud \n", data_ipv4->protocol);
		printf ("Header checksum: %hu \n", data_ipv4->header_checksum);
		printf ("Source IP address: %s \n", inet_ntoa (ip_source_struct));
		printf ("Destination IP address: %s \n", inet_ntoa(ip_dest_struct));
		printf ("Options: %u \n", data_ipv4->options);
	}


	printf ("\n \n");
}

free (buff); 

return 0;
}
