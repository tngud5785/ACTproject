#pragma once
#include "define.h"
#include "include.h"

typedef struct tcp_segment {
	u_int				seq_num;
	u_int				ack_num;
	u_short				len;
	struct tcp_segment* link;
} TcpSegment;