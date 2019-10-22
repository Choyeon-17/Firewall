#pragma once

#include <stdint.h>

struct ip_address
{
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;
};

struct ip_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl : 4; /* header length */
    unsigned int ip_v : 4;  /* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v : 4;  /* version */
    unsigned int ip_hl : 4; /* header length */
#endif
    uint8_t ip_tos;         /* type of service */
    uint16_t ip_len;        /* total length */
    uint16_t ip_id;         /* identification */
    uint16_t ip_off;        /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    uint8_t ip_ttl;         /* time to live */
    uint8_t ip_p;           /* protocol */
    uint16_t ip_sum;        /* checksum */
    ip_address ip_src;
    ip_address ip_dst;         /* src and dst address */
};