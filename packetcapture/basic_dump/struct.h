#pragma once

#include "define.h"
#include "include.h"
#include "ether_struct.h"
#include "ip_struct.h"
#include "tcp_struct.h"
#include "tls_struct.h"

#pragma pack(push, 1)
typedef struct udp_header {
	u_short		sport;
	u_short		dport;
	u_int		seqnum;
	u_int		acknum;
	u_short		thl_flags;
	u_short		win;
	u_short		crc;
	u_short		urgptr;
}udp_header;
#pragma pack(pop)	

#pragma pack(push, 1)
typedef struct arp_header {
	u_short		arp_hwtype;
	u_short		arp_ptype;
	u_char		arp_hwlen;
	u_char		arp_plen;
	u_short		arp_opcode;
	u_char		arp_shost[ETHER_ADDR_LEN];
	ip_address	saddr;
	u_char		arp_dhost[ETHER_ADDR_LEN];
	ip_address	daddr;
}arp_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct dns_header {
	u_short		arp_hwtype;
	u_short		arp_ptype;
	u_char		arp_hwlen;
	u_char		arp_plen;
	u_short		arp_opcode;
	u_char		arp_shost[ETHER_ADDR_LEN];
	ip_address	saddr;
	u_char		arp_dhost[ETHER_ADDR_LEN];
	ip_address	daddr;
}dns_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct packet {
	ether_header* eth;
	arp_header* arp;
	ip_header* ip;
	tcp_header* tcp;
	const unsigned char* mss;
	udp_header* udp;
	dns_header* dns;
	tls_header* tls;
	pcap_pkthdr* header;
	const unsigned char* app;
	int tcpCheck;
	int udpCheck;
}packet;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct signing_data {
	const char*	ch_random;		// Ŭ���̾�Ʈ ������ 32����Ʈ
	const char*	sh_random;		// ���� ������ 32����Ʈ 
	server_key_exchange*	ske;			// curve_type, name_curve, pubkey_length ��
	const char*				ske_pubkey;		// ECDHE �ӽ� ����Ű
	const char*				modulus;		// modulus ��
	const char*				publicexponent; // e ��
	const char* 			signature;		// �������� ��
	const char*	sign_len;
} SigningData;
#pragma pack(pop)