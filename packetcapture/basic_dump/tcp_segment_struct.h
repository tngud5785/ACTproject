#pragma once
#include "define.h"
#include "include.h"

typedef struct tcp_segment {
    u_int seq_num;
    u_int ack_num;
    const unsigned char* data;
    u_char data_length;
    u_char  src_ip;
    u_char  dst_ip;
    u_short src_port;
    u_short dst_port;
    const unsigned char* mss;
    struct tcp_segment* parent; // 부모 노드
    struct tcp_segment** children; // 자식 노드 배열
    u_int children_count; // 자식 노드 수
    u_int children_capacity; // 자식 노드 용량
} tcp_segment_t;

typedef struct tcp_segment_tree{
    tcp_segment_t* root; // 루트 노드
} tcp_segment_tree_t;
