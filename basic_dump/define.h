#pragma once

#define ETHER_LENGTH		14

#define _CRT_SECURE_NO_WARNINGS

#define ETHER_ADDR_LEN 6

#define IP_ADDR_LEN 4

#define IPv4_HEADER	0x0800
#define IPv6_HEADER 0x86DD
#define ARP_HEADER	0x0806
#define RARP_HEADER 0x0835

//protocol type
#define ICMP		1
#define IGMP		2
#define TCP			6
#define EGP			8
#define UDP			17
#define OSPF		89

//ethernet type
#define SYN			0x02
#define PUSH		0x08
#define ACK			0x10
#define FIN_ACK		0x11
#define SYN_ACK		0x12
#define PUSH_ACK	0x18

//record content type
#define CHANGE_CIPHER_SPEC 0x14
#define ALERT			   0x15
#define HANDSHAKE		   0x16
#define APPLICATION_DATA   0x17

//tls 1.2 handshake type
#define HELLO_REQUEST		0x00
#define CLIENT_HELLO		0x01
#define SERVER_HELLO		0x02
#define NEW_SESSION_TICKET	0x04
#define CERTIFICATE			0x0B
#define SERVER_KEY_EXCHANGE	0x0C
#define CERTIFICATE_REQUEST	0x0D
#define SERVER_HELLO_DONE	0x0E
#define CERTIFICATE_VERIFY	0x0F
#define CLIENT_KEY_EXCHANGE	0x10
#define FINISHED			0x14

//tls 1.3 handshake type
#define NEW_SESSION_TICKET		0x04
#define END_OF_EARLY_DATA		0x05
#define ENCRYPTED_EXTENSIONS	0x08
#define KEY_UPDATE				0x18
#define MESSAGE_HASH			0xFE

//TLS version
#define TLS_1_0 0x0301
#define TLS_1_1 0x0302
#define TLS_1_2 0x0303

//alert protocol Ω≈»£
#define CLOSE_NOTIFY		 0x00
#define NO_RENEGOTIATION	 0x64
#define UNEXPECTED_MESSAGE	 0x0A
#define BAD_RECORD_MAC		 0x14
#define DECRYPTION_FAILED	 0x15
#define HANDSHAKE_FAILURE	 0x28
#define BAD_CERTIFICATE		 0x2A
#define UNSUPPORTED_CERTIFICATE 0x2B
#define CERTIFICATE_REVOKE		0x2C
#define CERTIFICATE_EXPIRED		0x2D
#define UNRECOGNIZED_NAME		0x70