#include "ip_header.h"
#include "ether_header.h"
#include "tcp_header.h"
#include "define.h"
#include "struct.h"
#include "include.h"


void print_ip(ip_header* ip) {
	extern packet* pk;
	print_ether_header(pk->eth);
	printf("************************** IP Header **************************\n");
	printf("\n");
	printf("\n");
	printf("version: %d\n", ip->ip_version);
	printf("\n");
	printf("Header Length: %d bytes (%d)\n", (ip->ip_leng) * 4, ip->ip_leng);
	printf("\n");
	printf("Differentiated Services Field: 0x%02x\n", ip->tos);
	printf("\n");
	printf("Total Length: %d\n", ntohs(ip->tlen));
	printf("\n");
	printf("Identification: 0x%04x (%d)\n", ntohs(ip->identification), ntohs(ip->identification));
	printf("\n");
	if (((ntohs(ip->flags_fo)) >> 13 & 0x7) == 0) {
		printf("Flags: 0x0\n");
	}
	else if (((ntohs(ip->flags_fo)) >> 13 & 0x7) == 1) {
		printf("Flags: 0x1, More fragment\n");
	}
	else if (((ntohs(ip->flags_fo)) >> 13 & 0x7) == 2) {
		printf("Flags: 0x2, Don't fragment\n");
	}
	printf("\n");
	printf("Fragment Offset: %d\n", ntohs(ip->flags_fo) & 0x1FFF);
	printf("\n");
	printf("Time To Live: %d\n", ip->ttl);
	printf("\n");
	if (ip->proto == ICMP) {
		printf("Protocol: ICMP (%d)\n", ip->proto);
	}
	else if (ip->proto == IGMP) {
		printf("Protocol: IGMP (%d)\n", ip->proto);
	}
	else if (ip->proto == TCP) {
		printf("Protocol: TCP (%d)\n", ip->proto);
	}
	else if (ip->proto == EGP) {
		printf("Protocol: EGP (%d)\n", ip->proto);
	}
	else if (ip->proto == UDP) {
		printf("Protocol: UDP (%d)\n", ip->proto);
	}
	else if (ip->proto == OSPF) {
		printf("Protocol: OSPF (%d)\n", ip->proto);
	}
	else {
		printf("Protocol is Unknown (%d)\n", ip->proto);
	}
	printf("\n");
	printf("Header Checksum: 0x%04x\n", ntohs(ip->crc));
	printf("\n");
	printf("Source IP Address : %d.%d.%d.%d \n",
		ip->saddr.byte1,
		ip->saddr.byte2,
		ip->saddr.byte3,
		ip->saddr.byte4);
	printf("\n");
	printf("Destination IP Address : %d.%d.%d.%d \n",
		ip->daddr.byte1,
		ip->daddr.byte2,
		ip->daddr.byte3,
		ip->daddr.byte4);
	printf("\n");
}