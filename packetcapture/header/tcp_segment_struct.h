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
    struct tcp_segment* parent; // �θ� ���
    struct tcp_segment** children; // �ڽ� ��� �迭
    u_int children_count; // �ڽ� ��� ��
    u_int children_capacity; // �ڽ� ��� �뷮
} tcp_segment_t;

typedef struct tcp_segment_tree{
    tcp_segment_t* root; // ��Ʈ ���
} tcp_segment_tree_t;
