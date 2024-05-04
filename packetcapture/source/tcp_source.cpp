#include "tcp_header.h"
#include "ip_header.h"



void print_tcp(tcp_header* tcp, ip_header* ih) {
	extern packet* pk;

	print_ip(pk->ip);
	printf("************************* TCP Header *************************\n");
	printf("\n");
	printf("\n");
	printf("Source Port: %d\n", ntohs(tcp->sport));
	printf("\n");
	printf("Destination Port: %d\n", ntohs(tcp->dport));
	printf("\n");
	printf("Sequence Number: %u 	(relative sequence number)\n", ntohl(tcp->seqnum));
	printf("\n");
	printf("Acknowledgement Number: %u		(relative ack number)\n", ntohl(tcp->acknum));
	printf("\n");
	printf("Header Length: %d bytes (%d)\n", ((ntohs(tcp->thl_flags) >> 12) & 0xf) * 4, ((ntohs(tcp->thl_flags) >> 12) & 0xf));
	printf("\n");
	if ((ntohs(tcp->thl_flags) & 0x3F) == SYN) {
		printf("Flags: 0x%03x (SYN)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	else if ((ntohs(tcp->thl_flags) & 0x3F) == PUSH) {
		printf("Flags: 0x%03x (PUSH)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	else if ((ntohs(tcp->thl_flags) & 0x3F) == ACK) {
		printf("Flags: 0x%03x (ACK)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	else if ((ntohs(tcp->thl_flags) & 0x3F) == FIN_ACK) {
		printf("Flags: 0x%03x (FIN, ACK)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	else if ((ntohs(tcp->thl_flags) & 0x3F) == SYN_ACK) {
		printf("Flags: 0x%03x (SYN, ACK)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	else if ((ntohs(tcp->thl_flags) & 0x3F) == PUSH_ACK) {
		printf("Flags: 0x%03x (PUSH, ACK)\n", ntohs(tcp->thl_flags) & 0x3F);
		printf("\n");
	}
	printf("Window: %d\n", ntohs(tcp->win));
	printf("\n");
	printf("Checksum: 0x%04x\n", ntohs(tcp->crc));
	printf("\n");
	printf("Urgent Pointer: %d\n", tcp->urgptr);
	printf("\n");
}
