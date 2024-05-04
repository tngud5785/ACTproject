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
	if ((ip->ip_leng) * 4 > 20) {
		ip_header_option* iho;
		iho = (ip_header_option*)(pk->app + ETHER_LENGTH);
		switch (iho->option_copy_class_number) {
		case EOOL:
		{
			printf("Options: (%d bytes), End of Options List\n", iho->option_length);
			printf("\n");
			printf("IP Option - End of Options List (%d bytes)\n", iho->option_length);
			printf("\n");
			printf("Type: %d\n", iho->option_copy_class_number);
			if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
				printf("0... .... = Copy on fragmentation: No\n");
			}
			else {
				printf("1... .... = Copy on fragmentation: Yes\n");
			}
			if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
				printf(".00. .... = class: Contorl (0)\n");
			}
			else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
				printf(".01. .... = class: Undefined (1)\n");
			}
			else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
				printf(".10. .... = class: Debug (2)\n");
			}
			else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
				printf(".11. .... = class: Undefined (3)\n");
			}
			printf("...0 0000 = Number: End of Options List (0)\n");
			printf("\n");
			printf("Length: %d\n", iho->option_length);
			printf("\n");
			break;
		}
		case NOP:
		{
			printf("Options: (%d bytes), No Operation\n", iho->option_length);
			printf("\n");
			printf("IP Option - No Operation (%d bytes)\n", iho->option_length);
			printf("\n");
			printf("Type: %d\n", iho->option_copy_class_number);
			if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
				printf("0... .... = Copy on fragmentation: No\n");
			}
			else {
				printf("1... .... = Copy on fragmentation: Yes\n");
			}
			if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
				printf(".00. .... = class: Contorl (0)\n");
			}
			else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
				printf(".01. .... = class: Undefined (1)\n");
			}
			else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
				printf(".10. .... = class: Debug (2)\n");
			}
			else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
				printf(".11. .... = class: Undefined (3)\n");
			}
			printf("...0 0001 = Number: No Operation (1)\n");
			printf("\n");
			printf("Length: %d\n", iho->option_length);
			printf("\n");
			break;
		}
		case SEC:
		{
			printf("Options: (%d bytes), Security\n", iho->option_length);
			printf("\n");
			printf("IP Option - Security (%d bytes)\n", iho->option_length);
			printf("\n");
			printf("Type: %d\n", iho->option_copy_class_number);
			if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
				printf("0... .... = Copy on fragmentation: No\n");
			}
			else {
				printf("1... .... = Copy on fragmentation: Yes\n");
			}
			if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
				printf(".00. .... = class: Contorl (0)\n");
			}
			else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
				printf(".01. .... = class: Undefined (1)\n");
			}
			else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
				printf(".10. .... = class: Debug (2)\n");
			}
			else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
				printf(".11. .... = class: Undefined (3)\n");
			}
			printf("...0 0010 = Number: Security (2)\n");
			printf("\n");
			printf("Length: %d\n", iho->option_length);
			printf("\n");
			break;
		}
			case LSR:
			{
				printf("Options: (%d bytes), Loose Source Route\n", iho->option_length);
				printf("\n");
				printf("IP Option - Loose Source Route (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 0011 = Number: Loose Source Route (3)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case TS:
			{
				printf("Options: (%d bytes), Time Stamp\n", iho->option_length);
				printf("\n");
				printf("IP Option - Time Stamp (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 0100 = Number: Time Stamp (4)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case E_SEC:
			{
				printf("Options: (%d bytes), Extended Security\n", iho->option_length);
				printf("\n");
				printf("IP Option - Extended Security (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 0101 = Number: Extended Security (5)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case CIPSO:
			{
				printf("Options: (%d bytes), Commercial Security\n", iho->option_length);
				printf("\n");
				printf("IP Option - Commercial Security (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 0110 = Number: Commercial Security (6)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case RR:
			{
				printf("Options: (%d bytes), Record Route\n", iho->option_length);
				printf("\n");
				printf("IP Option - Record Route (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 0111 = Number: Record Route (7)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case STID:
			{
				printf("Options: (%d bytes), Stream ID\n", iho->option_length);
				printf("\n");
				printf("IP Option - Stream ID (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 1000 = Number: Stream ID (8)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case SSR:
			{
				printf("Options: (%d bytes), Strict Source Route\n", iho->option_length);
				printf("\n");
				printf("IP Option - Strict Source Route (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 1001 = Number: Strict Source Route (9)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case ZSU:
			{
				printf("Options: (%d bytes), Experimental Measurement\n", iho->option_length);
				printf("\n");
				printf("IP Option - Experimental Measurement (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 1010 = Number: Experimental Measurement (10)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case MTUP:
			{
				printf("Options: (%d bytes), MTU Probe\n", iho->option_length);
				printf("\n");
				printf("IP Option - MTU Probe (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 1011 = Number: MTU Probe (11)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case MTUR:
			{
				printf("Options: (%d bytes), MTU Reply\n", iho->option_length);
				printf("\n");
				printf("IP Option - MTU Reply (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 1100 = Number: MTU Reply (12)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case FINN:
			{
				printf("Options: (%d bytes), Experimental Flow Control\n", iho->option_length);
				printf("\n");
				printf("IP Option - Experimental Flow Control (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 1101 = Number: Experimental Flow Control (13)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case VISA:
			{
				printf("Options: (%d bytes), Experimental Access Control\n", iho->option_length);
				printf("\n");
				printf("IP Option - Experimental Access Control (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 1110 = Number: Experimental Access Control (14)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case ENCODE:
			{
				printf("Options: (%d bytes), ???\n", iho->option_length);
				printf("\n");
				printf("IP Option - ??? (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...0 1111 = Number: ??? (15)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case IMITD:
			{
				printf("Options: (%d bytes), IMI Traffic Descriptor\n", iho->option_length);
				printf("\n");
				printf("IP Option - IMI Traffic Descriptor (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...1 0000 = Number: IMI Traffic Descriptor (16)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case EIP:
			{
				printf("Options: (%d bytes), Extended Internet Protocol\n", iho->option_length);
				printf("\n");
				printf("IP Option - Extended Internet Protocol (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...1 0001 = Number: Extended Internet Protocol (17)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case TR:
			{
				printf("Options: (%d bytes), Traceroute\n", iho->option_length);
				printf("\n");
				printf("IP Option - Traceroute (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...1 0010 = Number: Traceroute (18)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case ADDEXT:
			{
				printf("Options: (%d bytes), Address Extension\n", iho->option_length);
				printf("\n");
				printf("IP Option - Address Extension (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...1 0011 = Number: Address Extension (19)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case RTRALT:
			{
				printf("Options: (%d bytes), Router Alert\n", iho->option_length);
				printf("\n");
				u_short data = ntohs(iho->option_data);

				if (data == 0) {
					printf("Router Alert: Router shall examine packet (%d)\n", data);
				}
				else if (data >= 1 && data <= 32) {
					printf("Router Alert: Aggregated Reservation Nesting Level (%d)\n", data);
				}
				else if (data >= 33 && data <= 64) {
					printf("Router Alert: QoS NSLP Aggregation Levels 0-31 (%d)\n", data);
				}
				else if (data == 65) {
					printf("Router Alert: NSIS NATFW NSLP (%d)\n", data);
				}
				else if (data >= 65503 && data <= 65534) {
					printf("Router Alert: Reserved for experimental use (%d)\n", data);
				}
				else if (data == 65535) {
					printf("Router Alert: Reserved (%d)\n", data);
				}
				else {
					printf("Router Alert: Unassigned (%d)\n", data);
				}
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				printf("\n");
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...1 0100 = Number: Router Alert (20) \n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case SDB:
			{
				printf("Options: (%d bytes), Selective Directed Broadcast\n", iho->option_length);
				printf("\n");
				printf("IP Option - Selective Directed Broadcast (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...1 0101 = Number: Selective Directed Broadcast (21)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case UNA:
			{
				printf("Options: (%d bytes), Unassigned\n", iho->option_length);
				printf("\n");
				printf("IP Option - Unassigned (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...1 0110 = Number: Unassigned (22)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case DPS:
			{
				printf("Options: (%d bytes), Dynamic Packet State\n", iho->option_length);
				printf("\n");
				printf("IP Option - Dynamic Packet State (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...1 0111 = Number: Dynamic Packet State (23)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case UMP:
			{
				printf("Options: (%d bytes), Upstream Multicast Pkt\n", iho->option_length);
				printf("\n");
				printf("IP Option - Upstream Multicast Pkt (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...1 1000 = Number: Upstream Multicast Pkt (24)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			case QS:
			{
				printf("Options: (%d bytes), Quick-Start\n", iho->option_length);
				printf("\n");
				printf("IP Option - Quick-Start (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...1 1001 = Number: Quick-Start (25)\n");
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
			default:
			{
				printf("Options: (%d bytes), RFC3692-style Experiment \n", iho->option_length);
				printf("\n");
				printf("IP Option - RFC3692-style Experiment  (%d bytes)\n", iho->option_length);
				printf("\n");
				printf("Type: %d\n", iho->option_copy_class_number);
				if (((iho->option_copy_class_number >> 7) & 0x01) == 0x01) {
					printf("0... .... = Copy on fragmentation: No\n");
				}
				else {
					printf("1... .... = Copy on fragmentation: Yes\n");
				}
				if (((iho->option_copy_class_number >> 5) & 0x11) == 0x00) {
					printf(".00. .... = class: Contorl (0)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x01) {
					printf(".01. .... = class: Undefined (1)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x10) {
					printf(".10. .... = class: Debug (2)\n");
				}
				else if (((iho->option_copy_class_number >> 5) & 0x11) == 0x11) {
					printf(".11. .... = class: Undefined (3)\n");
				}
				printf("...1 1110 = Number: RFC3692-style Experiment (%d)\n", iho->option_copy_class_number & 0x1F);
				printf("\n");
				printf("Length: %d\n", iho->option_length);
				printf("\n");
				break;
			}
		}
	}
}