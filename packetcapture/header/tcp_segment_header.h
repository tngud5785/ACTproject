#pragma once
#include "struct.h"
#include "tcp_segment_struct.h"


void init_tree(tcp_segment_tree_t* tree);
tcp_segment_t* create_segment(packet* pk);
void add_child(tcp_segment_t* parent, tcp_segment_t* child);
void remove_segment(tcp_segment_tree_t* tree, tcp_segment_t* segment);
void traverse_tree(tcp_segment_t* node, int level);