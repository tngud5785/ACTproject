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
}TcpHeader;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tcp_header_option {
	u_char		tcp_kind;
}TcpHeaderOption;
#pragma pack(pop)


#pragma pack(push, 1)
typedef struct tcp_header_option_eol {
	TcpHeaderOption  tcp_header_option;
}TcpHeaderOptionEol;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tcp_header_option_nop {
	TcpHeaderOption  tcp_header_option;
}TcpHeaderOptionNop;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tcp_header_option_mss {
	TcpHeaderOption		tcp_header_option;
	u_char				mss_length;
	u_short				mss_value;
}TcpHeaderOptionMss;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tcp_header_option_wscale {
	TcpHeaderOption		tcp_header_option;
	u_char				wscale_length;
	u_char				wscale_shift_count;
}TcpHeaderOptionWscale;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tcp_header_option_sackper {
	TcpHeaderOption		tcp_header_option;
}TcpHeaderOptionSackPermitted;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tcp_header_option_sack {
	TcpHeaderOption		tcp_header_option;
	u_char				sack_length;

}TcpHeaderOptionSack;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tcp_header_option_timestamp {
	TcpHeaderOption		tcp_header_option;
	u_char				timestamp_length;
	u_int				timestamp_value;
	u_int				timestamp_echo_reply;
}TcpHeaderOptionTimestamp;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tcp_header_option_uto {
	TcpHeaderOption  tcp_header_option;


}TcpHeaderOptionUto;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tcp_header_option_tcp_a0 {
	TcpHeaderOption		tcp_header_option;
	u_char				a0_length;

}TcpHeaderOptionTcpA0;
#pragma pack(pop)