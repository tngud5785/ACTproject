#include "tcp_segment_header.h"

void reassembled_segment(tcp_header* th, const unsigned char* pkt_data) {
	extern packet* pk;
	char* tcp_payload;
	tcp_payload = (char*)malloc(ntohs(pk->ip->tlen) - (pk->ip->ip_leng) * 4 - ((ntohs(pk->tcp->thl_flags) >> 12) & 0xf) * 4);
	tcp_payload = (char*)(pkt_data + ETHER_LENGTH + (pk->ip->ip_leng * 4));
	if ((tcp_payload - sizeof(tls_header) + pk->tls->tls_length) != 0) {

	}
	else {

	}
}