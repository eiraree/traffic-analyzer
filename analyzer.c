#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>

#define IPV4_OPTIONS(HEADER_SIZE, OPTIONS) ((HEADER_SIZE > 5) ? (OPTIONS) : 0) 

int main () {
ssize_t rec = 0;
char * buff = NULL;
int sock = -1;
int i = 0;

struct ether_header {
	unsigned char dest_mac [6];
	unsigned char src_mac [6];
	unsigned short eth_type;
} __attribute__((__packed__));

struct ipv4_header {
	unsigned char version_header_size; 			/* 4 bits for version, 4 bits for header size */
	unsigned char dscp_ecn;  		   			/* 4 bits for DSCP, 4 bits for ECN */
	unsigned short packet_size; 
	unsigned short identificator;
	unsigned short flags_fragment_offset;		/* 3 bits for flags, 13 bits for fragment offset */
	unsigned char time_to_live;
	unsigned char protocol;
	unsigned short header_checksum;
	unsigned int ip_source;
	unsigned int ip_dest;
	unsigned int options;
}__attribute__((__packed__)); 

struct tcp_header {
	unsigned short source_port; 
	unsigned short dest_port;
	unsigned int seq_num;
	unsigned int ack_num;
	unsigned char data_offset_reserved;			/* 4 bits for data offset, 4 bits reserved */
	unsigned char tcp_flags;					/* CWR, ECE, URG, ACK, PSH, RST, SYN, FIN */
	unsigned short win_size;
	unsigned short checksum;
	unsigned short urg_pointer;
 	unsigned int options; 
}__attribute__((__packed__)); 

struct types_array {
	unsigned short type;
	char * string;
};

struct types_array table_of_types_ll [] = {
	{0x0800, "IPv4"},
	{0x0806, "ARP"},
	{0x8137, "IPX"},
	{0x888E, "EAP"},
};

struct types_array table_of_types_ipl [] = {
	{6, "TCP"},
	{17, "UDP"},
	{40, "IL Protocol"},
	{47, "Generic Routing Encapsulation"},
	{50, "Encapsulating Security Payload"},
	{51, "Authentication Header"},
	{132, "Stream Control Transmission Protocol"},
};

struct ether_header * data_packet; 
struct ipv4_header * data_ipv4;
struct tcp_header * data_tcp;

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

printf("ether + ip = %lu\n", sizeof(struct ether_header) + sizeof(struct ipv4_header));

buff = (char*) malloc (ETH_FRAME_LEN); 

while (1) {
	rec = recvfrom (sock, buff, ETH_FRAME_LEN, 0, NULL, 0);
	if (rec == -1)
		return -1;

	data_packet = (struct ether_header *) buff;

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
		if (table_of_types_ll[i].type ==  ntohs(data_packet->eth_type)) {
		printf ("EtherType: %#.4x is %s\n", ntohs(data_packet->eth_type), table_of_types_ll[i].string);
		break;
		}
	}

	if (ntohs(data_packet->eth_type) == 0x0800) {

		data_ipv4 = (struct ipv4_header *) &buff[sizeof(struct ether_header)];

		/* Network layer */

		ip_source_struct.s_addr = data_ipv4->ip_source;
		ip_dest_struct.s_addr = data_ipv4->ip_dest;

		printf ("Version: %hhu \n", (data_ipv4->version_header_size >> 4));
		printf ("Header size: %hhu \n", (data_ipv4->version_header_size & 0xF));
		printf ("DCSP: %u \n", (data_ipv4->dscp_ecn >> 2));
		printf ("ECN: %u \n", (data_ipv4->dscp_ecn & 3));
		printf ("Packet size: %hu \n", ntohs(data_ipv4->packet_size));
		printf ("Identificator: %hu \n", ntohs(data_ipv4->identificator));
		printf ("Flags: %u \n", ntohs(data_ipv4->flags_fragment_offset) >> 13);
		printf ("Fragment offset: %u \n", ntohs(data_ipv4->flags_fragment_offset) & 0x1FFF);
		printf ("Time to live: %hhu \n", data_ipv4->time_to_live);

		for (i = 0; i < 7; i++) {
			if (table_of_types_ipl[i].type == data_ipv4->protocol) {	
				printf ("Protocol: %hhu is %s \n", data_ipv4->protocol, table_of_types_ipl[i].string);
				break;
			}
		}
		printf ("Header checksum: %hu \n", ntohs(data_ipv4->header_checksum));
		printf ("Source IP address: %s \n", inet_ntoa (ip_source_struct));
		printf ("Destination IP address: %s \n", inet_ntoa(ip_dest_struct));
		printf ("Options: %u \n", IPV4_OPTIONS ((data_ipv4->version_header_size & 0xF), ntohs(data_ipv4->options)));

		/* Transport layer */
		for (i = 0; i < 7; i++) {
			if (table_of_types_ipl[i].type == data_ipv4->protocol)  { 

				data_tcp = (struct tcp_header *) &buff [sizeof(struct ether_header) + ((data_ipv4->version_header_size & 0xF) * 4)];

				printf ("Source port: %hu \n", ntohs (data_tcp->source_port));
				printf ("Destination port: %hu \n", ntohs (data_tcp->dest_port));
				printf ("Sequence number: %u \n", ntohs (data_tcp->seq_num));
				printf ("Acknoulegement number: %u \n", ntohs (data_tcp->ack_num));
				printf ("Data offset: %hu \n", (data_tcp->data_offset_reserved >> 4));
				printf ("Reserved: %hu \n", data_tcp->data_offset_reserved & 0xF);
				printf ("TCP layer flags: %u \n", data_tcp->tcp_flags);
				printf ("Window size: %u \n", ntohs(data_tcp->win_size));
				printf ("Checksum: %hhu \n", ntohs (data_tcp->checksum));
				printf ("Urgent pointer: %hhu \n", ntohs(data_tcp->urg_pointer));
				printf ("Options: %u \n", ntohs(data_tcp->options));
			}
	}
}

	printf ("\n \n");
}

free (buff); 

return 0;
}
