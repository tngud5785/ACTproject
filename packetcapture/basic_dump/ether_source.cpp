#include "ether_header.h"


void print_ether_header(ether_header* eh) {
	extern packet* pk;

	mac* srcmac;
	mac* destmac;
	u_short ptype;

	destmac = (mac*)eh;
	srcmac = (mac*)((u_char*)eh + 6);
	ptype = ntohs(eh->ether_type);

	printf("******************** Ethernet Frame Header ********************\n"); //Ethernet Frame Header
	printf("\n");
	printf("\n");
	printf("Destination : %02x:%02x:%02x:%02x:%02x:%02x \n",
		destmac->byte1,
		destmac->byte2,
		destmac->byte3,
		destmac->byte4,
		destmac->byte5,
		destmac->byte6);
	printf("\n");
	printf("Source : %02x:%02x:%02x:%02x:%02x:%02x \n",
		srcmac->byte1,
		srcmac->byte2,
		srcmac->byte3,
		srcmac->byte4,
		srcmac->byte5,
		srcmac->byte6);
	printf("\n");

	if (ntohs(eh->ether_type) == IPv4_HEADER) {
		printf("Type: IPv4 (0x%04x)\n", ptype);
	}
	else if (ntohs(eh->ether_type) == ARP_HEADER) {
		printf("Type: ARP(0x%04x)\n", ptype);
	}
	else {
		printf("Type: Unknown(0x%04x)\n", ptype);
	}
	printf("\n");

	if (pk->header->len <= 60 && pk->header->len > 54 && (ntohs(eh->ether_type) == IPv4_HEADER)) {
		printf("Padding: ");
		for (int i = 1; i <= ntohs(pk->ip->tlen) - ETHER_LENGTH - ((pk->ip->ip_leng) * 4) - (((ntohs(pk->tcp->thl_flags) >> 12) & 0xf) * 4); i++) {
			printf("00");
		}
		printf("\n");
	}
	else if(pk->header->len <= 60 && pk->header->len > 54 && (ntohs(eh->ether_type) == ARP_HEADER)) {
		printf("Padding: ");
		for (int i = 1; i <= ntohs(pk->ip->tlen) - ETHER_LENGTH - ((pk->ip->ip_leng) * 4) - (((ntohs(pk->tcp->thl_flags) >> 12) & 0xf) * 4); i++) {
			printf("00");
		}
		printf("\n");
	}
	printf("\n");
}
