#pragma once

#include "define.h"
#include "include.h"

#pragma pack(push, 1)
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}IpAddress;
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
}IpHeader;
#pragma pack(pop)

typedef struct ip_header_option {
	IpHeader	option_ip_header;
	u_char		option_copy_class_number;
	u_char		option_length;
	u_short		option_data;
} IpHeaderOption;




