#include <cstdio>
#include <iostream>
#include <cstring>
#include <vector>
#include <fstream>
#include <stdlib.h>
#include <unordered_map>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "../header/packet.h"
#include "../header/Protocol/all.h"
#include "../header/Parser/http.h"

using namespace std;
unordered_map<string, bool>rules;

static u_int32_t packet_filter(struct nfq_data *tb, bool *is_accept)
{
    unsigned char *data;
    int id = 0, packet_index = 0, ret;
    u_int32_t mark, ifi;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;

    unordered_map<string, bool>::iterator rules_it;
    
    ph = nfq_get_msg_packet_hdr(tb);

    if (ph)
    {
        id = ntohl(ph->packet_id);

        if (ntohs(ph->hw_protocol) == ETHERTYPE_IP)
        {
            ret = nfq_get_payload(tb, &data);
            
            if (ret >= 0)
            {
                const ip_header *ip = (ip_header *)data;
                packet_index += sizeof(ip_header);

                char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ip->ip_src), ip_src, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(ip->ip_dst), ip_dst, INET_ADDRSTRLEN);

                char rules_check_ip_src[29], rules_check_ip_dst[29];
                sprintf(rules_check_ip_src, "Drop IPv4 src %s", ip_src);
                sprintf(rules_check_ip_dst, "Drop IPv4 dst %s", ip_dst);

                rules_it = rules.find(rules_check_ip_src);
                *is_accept = rules_it != rules.end() ? false : *is_accept && true;
                rules_it = rules.find(rules_check_ip_dst);
                *is_accept = rules_it != rules.end() ? false : *is_accept && true;

                if (ip->ip_p == IPPROTO_TCP)
                {
                    const tcp_header *tcp = (tcp_header *)(data + packet_index);
                    packet_index += sizeof(tcp_header);
                    uint32_t tcp_size = ntohs(ip->ip_len) - ((ip->ip_hl + tcp->th_off) * 4);

                    char rules_check_port_src[19], rules_check_port_dst[19];
                    sprintf(rules_check_port_src, "Drop TCP src %d", ntohs(tcp->th_sport));
                    sprintf(rules_check_port_dst, "Drop TCP dst %d", ntohs(tcp->th_dport));

                    rules_it = rules.find(rules_check_port_src);
                    *is_accept = rules_it != rules.end() ? false : *is_accept && true;
                    rules_it = rules.find(rules_check_port_dst);
                    *is_accept = rules_it != rules.end() ? false : *is_accept && true;

                    if (tcp_size > 0)
                    {
                        if (ntohs(tcp->th_dport) == 80)
                        {
                            if (is_http_protocol(data + packet_index, tcp_size))
                            {
                                unordered_map<string, string>http_header;
                                parse_http(data + packet_index, tcp_size, &http_header);

                                string host = http_header["Host"];
                                string method = http_header["Method"];

                                char rules_check_http_host[2019], rules_check_http_method[26];
                                sprintf(rules_check_http_host, "Drop HTTP host %s", host.c_str());
                                sprintf(rules_check_http_method, "Drop HTTP method %s", method.c_str());

                                rules_it = rules.find(rules_check_http_host);
                                *is_accept = rules_it != rules.end() ? false : *is_accept && true;
                                if (!*is_accept)
                                    cout << "[*] HTTP host block: " << host << endl;

                                rules_it = rules.find(rules_check_http_method);
                                *is_accept = rules_it != rules.end() ? false : *is_accept && true;
                                if (!*is_accept)
                                    cout << "[*] HTTP method block: " << method << endl;
                            }
                        }
                    }
                }
            }
        }
    }

    return id;
}

static int packet_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    bool *is_accept = new bool(true);
    u_int32_t id = packet_filter(nfa, is_accept);

    return nfq_set_verdict(qh, id, *is_accept ? NF_ACCEPT : NF_DROP, 0, NULL);
}

int main(int argc, char *argv[])
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd, rv;
    char buf[4096] __attribute__((aligned));

    cout << "[*] Opening library handle" << endl;
    h = nfq_open();
    if (!h)
    {
        cout << "[*] Error during nfq_open()" << endl;
        exit(1);
    }

    cout << "[*] Unbinding existing nf_queue handler for AF_INET (if any)" << endl;
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        cout << "[*] Error during nfq_unbind_pf()" << endl;
        exit(1);
    }

    cout << "[*] Binding nfnetlink_queue as nf_queue handler for AF_INET" << endl;
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        cout << "[*] Error during nfq_bind_pf()" << endl;
        exit(1);
    }

    cout << "[*] Binding this socket to queue '0'" << endl;
    qh = nfq_create_queue(h, 0, &packet_callback, NULL);
    if (!qh)
    {
        cout << "[*] Error during nfq_create_queue()" << endl;
        exit(1);
    }

    cout << "[*] Setting copy_packet mode" << endl;
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        cout << "[*] Can not set packet_copy mode" << endl;
        exit(1);
    }

    cout << "[*] Read rules file" << endl;
    cout << argv[0] << endl;

    string bin_exe_dir(argv[0]);
    string bin_exe_dir_base = bin_exe_dir.substr(0, bin_exe_dir.find_last_of("/"));
    ifstream rule_file(bin_exe_dir_base + "/rules.txt");

    if (!rule_file)
        cout << "[*] Rules file not exist" << endl;
    
    cout << bin_exe_dir_base + "/rules.txt" << endl;

    string rule_str;

    while (getline(rule_file, rule_str))
    {
        rules.insert(make_pair(rule_str, true));
    }

    cout << "[*] Rules size: " << rules.size() << endl;
    cout << "[*] Rules load success" << endl;

    fd = nfq_fd(h);

    while (true)
    {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
        {
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        if (rv < 0 && errno == ENOBUFS)
        {
            cout << "[*] Losing packets" << endl;
            continue;
        }

        perror("recv failed");
        break;
    }

    cout << "[*] Unbinding from queue 0" << endl;
    nfq_destroy_queue(qh);

#ifdef INSANE
    cout << "[*] Unbinding from AF_INET" << endl;
    nfq_unbind_pf(h, AF_INET);

#endif
    cout << "[*] Closing library handle" << endl;
    nfq_close(h);

    exit(0);
}