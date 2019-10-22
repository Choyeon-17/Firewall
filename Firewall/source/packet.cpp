#include <cstdio>
#include <cstring>
#include <stdint.h>
#include <netinet/in.h>
#include "../../header/protocol/all.h"

#define MAX_MTU 1500

void print_mac_address(mac_address mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac.oui[0], mac.oui[1], mac.oui[2], mac.nic[0], mac.nic[1], mac.nic[2]);
}

void print_ip_address(ip_address ip)
{
    printf("%d.%d.%d.%d", ip.a, ip.b, ip.c, ip.d);
}

void print_tcp_port(uint16_t port)
{
    printf("%d", port);
}

void print_packet(const unsigned char *p, uint32_t size)
{
    int len = 0;

    while (len < size)
    {
        if (!(len % 16))
            printf("%04X  ", len);
        printf("%02X ", *(p + len));
        if (!((len + 1) % 8))
            printf("   ");

        len++;

        if (!(len % 16) || (size - len) == 0)
        {
            int length = (size - len) == 0 ? size % 16 : 16;

            if (length < 16)
            {
                for (int i = 0; i < (16 - length); i++)
                {
                    printf("   ");
                    if (!((i + 1) % 8))
                        printf("   ");
                }
                printf("   ");
            }

            for (int i = 0; i < length; i++)
            {
                uint8_t now_char = *(p + (len - (length - i)));

                if (now_char >= 33 && now_char <= 126)
                    printf("%c ", now_char);
                else
                    printf(". ");
                if (!((i + 1) % 8))
                    printf("   ");
            }
            printf("\n");
        }
    }
}

bool equal_ip_address(ip_address x, ip_address y)
{
    return memcmp(&x, &y, sizeof(ip_address)) == 0;
}

bool equal_mac_address(mac_address x, mac_address y)
{
    return memcmp(&x, &y, sizeof(mac_address)) == 0;
}