#pragma once
#include "define.h"
#include "include.h"

typedef struct mac_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ether_header {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
}ether_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ip_header {
	u_char		ip_leng : 4;
	u_char		ip_version : 4;
	u_char		tos;
	u_short		tlen;
	u_short		identification;
	u_short		flags_fo;
	u_char		ttl;
	u_char		proto;
	u_short		crc;
	ip_address	saddr;
	ip_address	daddr;
	u_int		op_pad;
}ip_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tcp_header {
	u_short		sport;
	u_short		dport;
	u_int		seqnum;
	u_int		acknum;
	u_short		thl_flags;
	u_short		win;
	u_short		crc;
	u_short		urgptr;
}tcp_header;
#pragma pack(pop)	

#pragma pack(push, 1)
typedef struct tls_header {
	u_short		sport;
	u_short		dport;
	u_int		seqnum;
	u_int		acknum;
	u_short		thl_flags;
	u_short		win;
	u_short		crc;
	u_short		urgptr;
}tls_header;
#pragma pack(pop)

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
typedef struct record_layer {
	u_char		rl_type;
	u_short		rl_version;
	u_short		rl_length;
}record_layer;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ccs_proto {
	u_char		ccs_type;
	u_short		ccs_version;
	u_short		ccs_leng;
	u_char		ccs_message;
}ccs_proto;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct alert_proto {
	u_char		alert_type;
	u_short		alert_version;
	u_short		alert_leng;
	u_char		alert_level;
	u_char		alert_descl;
}alert_proto;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct application_proto {
	u_char		app_type;
	u_short		app_version;
	u_short		app_leng;
	u_char		app_enc_data[];
}application_proto;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct handshake_protocol {
	u_int		handshake_type_leng;
	u_short		handshake_version;
}handshake_protocol;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct hello_request {

}hello_request;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_hello {
	u_int		ch_gmt;
	u_char		ch_random_bytes[28];
}client_hello;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_hello {

}server_hello;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct new_session_ticket {

}new_session_ticket;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct certificate {

}certificate;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_key_exchange {

}server_key_exchange;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct certificate_request {

}certificate_request;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct server_hello_done {

}server_hello_done;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct certificate_verify {

}certificate_verify;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct client_key_exchange {

}client_key_exchange;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct finished {

}finished;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct packet {
	ether_header* eth;
	arp_header* arp;
	ip_header* ip;
	tcp_header* tcp;
	udp_header* udp;
	dns_header* dns;
	tls_header* tls;
	pcap_pkthdr* header;
	const unsigned char* app;
	int tcpCheck;
	int udpCheck;
}packet;
#pragma pack(pop)