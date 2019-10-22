#pragma once

#include <stdint.h>
#include "ethernet.h"
#include "ip.h"

/* ARP protocol HARDWARE identifiers. */

#define ARPHRD_ETHER 1    /* Ethernet 10/100Mbps.  */
#define ARPOP_REQUEST 1   /* ARP request.  */
#define ARPOP_REPLY 2     /* ARP reply.  */
#define ARPOP_RREQUEST 3  /* RARP request.  */
#define ARPOP_RREPLY 4    /* RARP reply.  */
#define ARPOP_InREQUEST 8 /* InARP request.  */
#define ARPOP_InREPLY 9   /* InARP reply.  */
#define ARPOP_NAK 10      /* (ATM)ARP NAK.  */

#define ARPPRO_IPV4 0x0800

#define MAC_LENGTH 6
#define IPV4_LENGTH 4

struct __attribute__((aligned(1), packed)) arp_header
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    mac_address sender_mac;
    ip_address sender_ip;
    mac_address target_mac;
    ip_address target_ip;
};

struct __attribute__((aligned(1), packed)) s_arp
{
    mac_address sender_mac;
    ip_address sender_ip;
    mac_address target_mac;
    ip_address target_ip;
};