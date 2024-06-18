#pragma once
#include "struct.h"

unsigned char* hex_to_bin(const char* hex, int out_len);
void parse_certificate(const unsigned char* cert_data, size_t cert_len);