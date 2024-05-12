#include "tcp_header.h"
#include "ip_header.h"

void print_tcp(tcp_header* tcp, ip_header* ih, const unsigned char* pkt_data) {
	extern packet* pk;
	int tcp_option_offset = 0;
	int option_start = 0;
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
	
	/*if (((ntohs(tcp->thl_flags) >> 12) & 0xf) * 4 > 20){
		printf("Options: (%d bytes)\n", (((ntohs(tcp->thl_flags) >> 12) & 0xf) * 4 - 20));
		printf("\n");
		while ((((ntohs(tcp->thl_flags) >> 12) & 0xf) * 4 - 20) != tcp_option_offset) {
			tcp_header_option* tho;
			option_start = ETHER_LENGTH + (pk->ip->ip_leng) * 4 + (((ntohs(tcp->thl_flags) >> 12) & 0xf) * 4 - 20) + tcp_option_offset;
			tho = (tcp_header_option*)(pkt_data + option_start);
			switch (tho->tcp_kind) {
				case OPT_EOL:
					tcp_header_option_eol* thoe;
					thoe = (tcp_header_option_eol*)(pkt_data + option_start);
					printf("TCP Option - End-of-Option (EOL)\n");
					printf("\n");
					printf("Kind: End-of-Option (%d)\n", thoe->tcp_header_option.tcp_kind);
					printf("\n");
					tcp_option_offset += 1;
					break;
				case OPT_NOP:
					tcp_header_option_nop* thop;
					thop = (tcp_header_option_nop*)(pkt_data + option_start);
					printf("TCP Option - No-Operation (NOP)\n");
					printf("\n");
					printf("Kind: No-Operation (%d)\n", thop->tcp_header_option.tcp_kind);
					printf("\n");
					tcp_option_offset += 1;
					break;
				case OPT_MSS:
					tcp_header_option_mss* thom;
					thom = (tcp_header_option_mss*)(pkt_data + option_start);
					printf("TCP Option - Maximum segment size: %d bytes\n", ntohs(thom->mss_value));
					printf("\n");
					printf("Kind: Maximum Segment Size (%d)\n", thom->tcp_header_option.tcp_kind);
					printf("\n");
					printf("Length: %d\n", thom->mss_length);
					printf("\n");
					printf("MSS Value: %d", ntohs(thom->mss_value));
					printf("\n");
					tcp_option_offset += 4;
					break;
				case OPT_WSCALE:
					tcp_header_option_wscale* thow;
					thow = (tcp_header_option_wscale*)(pkt_data + option_start);
					printf("TCP Option - Window scale: %d (multiply by %d)\n", thow->wscale_shift_count, (int)pow(2,thow->wscale_shift_count));
					printf("\n");
					printf("Kind: Window scale (%d)\n", thow->tcp_header_option.tcp_kind);
					printf("\n");
					printf("Length: %d\n", thow->wscale_length);
					printf("\n");
					printf("[Multiplier: %d]\n", (int)pow(2, thow->wscale_shift_count));
					printf("\n");
					tcp_option_offset += 3;
					break;
				case OPT_SACKPERMITTED:
					tcp_header_option_sackper* thosp;
					thosp = (tcp_header_option_sackper*)(pkt_data + option_start);
					printf("TCP Option - SACK permitted\n");
					printf("\n");
					printf("Kind: SACK permitted (%d)\n", thosp->tcp_header_option.tcp_kind);
					printf("\n");
					tcp_option_offset += 2;
					break;
				case OPT_SACK:
					tcp_header_option_sack* thos;
					thos = (tcp_header_option_sack*)(pkt_data + option_start);
					thos = (tcp_header_option_sack*)malloc(thos->sack_length);
					thos = (tcp_header_option_sack*)(pkt_data + option_start);
					printf("TCP Option - SACK\n");
					printf("\n");
					printf("Kind: No-Operation (%d)\n", thos->tcp_header_option.tcp_kind);
					printf("\n");
					tcp_option_offset += thos->sack_length;
					break;
				case OPT_TIMESTAMP:
					tcp_header_option_timestamp* thots;
					thots = (tcp_header_option_timestamp*)(pkt_data + option_start);
					printf("TCP Option - No-Operation (NOP)\n");
					printf("\n");
					printf("Kind: No-Operation (%d)\n", thots->tcp_header_option.tcp_kind);
					printf("\n");
					printf("Length: %d\n", thots->timestamp_length);
					printf("\n");
					tcp_option_offset += 10;
					break;
				case OPT_USER_TIMEOUT:
					tcp_header_option_uto* thou;
					thou = (tcp_header_option_uto*)(pkt_data + option_start);
					printf("TCP Option - No-Operation (NOP)\n");
					printf("\n");
					printf("Kind: No-Operation (%d)\n", thou->tcp_header_option.tcp_kind);
					printf("\n");
					tcp_option_offset += 4;
					break;
				case OPT_TCP_A0:
					tcp_header_option_tcp_a0* thota;
					thota = (tcp_header_option_tcp_a0*)(pkt_data + option_start);
					thota = (tcp_header_option_tcp_a0*)malloc(thota->a0_length);
					thota = (tcp_header_option_tcp_a0*)(pkt_data + option_start);
					printf("TCP Option - No-Operation (NOP)\n");
					printf("\n");
					printf("Kind: No-Operation (%d)\n", thota->tcp_header_option.tcp_kind);
					printf("\n");
					tcp_option_offset += thota->a0_length;
					break;
				default:
					printf("TCP Option - Unknown\n");
					printf("\n");
					printf("Kind: Unknown (%d)\n", tho->tcp_kind);
					printf("\n");
					tcp_option_offset += sizeof(tho->tcp_kind);
					break;
			}
		}
	}*/
}
