#pragma once

#include <stdint.h>
#include "protocol/all.h"

void print_mac_address(mac_address);
void print_ip_address(ip_address);
void print_tcp_port(uint16_t);

void packet_parse(eth_header*, const u_char *, int *);

void print_packet(const unsigned char *, uint32_t);
void _print_packet(const unsigned char *, uint32_t);

bool equal_mac_address(mac_address, mac_address);
bool equal_ip_address(ip_address, ip_address);