#pragma once

#include <cstring>
#include <stdint.h>
#include <unordered_map>

using namespace std;

bool parse_http(uint8_t *, uint32_t, unordered_map<string, string> *);
bool check_http_method(uint8_t *, uint8_t *, uint32_t);
bool is_http_protocol(uint8_t *, uint32_t);