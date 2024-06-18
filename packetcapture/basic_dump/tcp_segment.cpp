//#include "tcp_segment_header.h"
//
//void init_tree(tcp_segment_tree_t* tree) {
//    tree->root = NULL;
//}
//
//tcp_segment_t* create_segment(packet* pk) {
//    extern packet* pk;
//    tcp_segment_t* segment = (tcp_segment_t*)malloc(sizeof(tcp_segment_t));
//    segment->seq_num = pk->tcp->seqnum;
//    segment->ack_num = pk->tcp->acknum;
//    segment->data = pk->app;
//    segment->data_length = sizeof(pk->app);
//    segment->src_ip = pk->ip->saddr.byte1 + pk->ip->saddr.byte2 + pk->ip->saddr.byte3 + pk->ip->saddr.byte4;
//    segment->dst_ip = pk->ip->daddr.byte1 + pk->ip->daddr.byte2 + pk->ip->daddr.byte3 + pk->ip->daddr.byte4;
//    segment->src_port = pk->tcp->sport;
//    segment->dst_port = pk->tcp->dport;
//    segment->mss = pk->mss;
//    segment->parent = NULL;
//    segment->children_count = 0;
//    segment->children_capacity = 2;
//    segment->children = (tcp_segment_t**)malloc(sizeof(tcp_segment_t*) * segment->children_capacity);
//    return segment;
//}
//
//void add_child(tcp_segment_t* parent, tcp_segment_t* child) {
//    if (parent->children_count == parent->children_capacity) {
//        parent->children_capacity *= 2;
//        parent->children = (tcp_segment_t**)realloc(parent->children, sizeof(tcp_segment_t*) * parent->children_capacity);
//    }
//    child->parent = parent;
//    parent->children[parent->children_count++] = child;
//}
//
//void remove_segment(tcp_segment_tree_t* tree, tcp_segment_t* segment) {
//    if (segment->parent) {
//        tcp_segment_t* parent = segment->parent;
//        for (int i = 0; i < parent->children_count; ++i) {
//            if (parent->children[i] == segment) {
//                for (int j = i; j < parent->children_count - 1; ++j) {
//                    parent->children[j] = parent->children[j + 1];
//                }
//                parent->children_count--;
//                break;
//            }
//        }
//    }
//    else {
//        tree->root = NULL;
//    }
//
//    for (int i = 0; i < segment->children_count; ++i) {
//        remove_segment(tree, segment->children[i]);
//    }
//
//    free(segment->children);
//    free(segment);
//}
//
//void traverse_tree(tcp_segment_t* node, int level) {
//    if (!node) return;
//
//    for (int i = 0; i < level; ++i) printf("  ");
//    printf("Seq: %d, Ack: %d, Data: %s\n", node->seq_num, node->ack_num, node->data);
//
//    for (int i = 0; i < node->children_count; ++i) {
//        traverse_tree(node->children[i], level + 1);
//    }
//}
//
//void print_tls(tcp_segment_t* segment) {
//    printf("TLS Display: Complete TCP segment!\n");
//    printf("Src IP: %s, Dst IP: %s, Src Port: %d, Dst Port: %d, Seq: %d, Ack: %d, Data: %s\n",
//        segment->src_ip, segment->dst_ip, segment->src_port, segment->dst_port,
//        segment->seq_num, segment->ack_num, segment->data);
//}
//
//int main() {
//    tcp_segment_tree_t tree;
//    init_tree(&tree);
//
//    tcp_segment_t* root = create_segment(1, 1, "Root", 4, "192.168.0.1", "192.168.0.2", 12345, 80, 0);
//    tree.root = root;
//
//    tcp_segment_t* child1 = create_segment(2, 2, "Child1", 6, "192.168.0.1", "192.168.0.2", 12345, 80, 0);
//    add_child(root, child1);
//
//    tcp_segment_t* child2 = create_segment(3, 3, "Child2", 6, "192.168.0.1", "192.168.0.2", 12345, 80, 0);
//    add_child(root, child2);
//
//    tcp_segment_t* grandchild1 = create_segment(4, 4, "Grandchild1", 11, "192.168.0.1", "192.168.0.2", 12345, 80, 0);
//    add_child(child1, grandchild1);
//
//    printf("Initial Tree:\n");
//    traverse_tree(tree.root, 0);
//
//    printf("\nRemoving child2:\n");
//    remove_segment(&tree, child2);
//
//    printf("Updated Tree:\n");
//    traverse_tree(tree.root, 0);
//
//    return 0;
//}