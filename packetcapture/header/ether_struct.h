#pragma once

#include "define.h"
#include "include.h"

#pragma pack(push, 1)
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
typedef struct ether_header {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
}ether_header;
#pragma pack(pop)