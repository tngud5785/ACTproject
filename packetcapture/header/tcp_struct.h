#pragma once

#include "define.h"
#include "include.h"

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