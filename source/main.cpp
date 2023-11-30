#include <iostream>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "ip.h"

#define JOURNALD_LOGGING

#ifndef JOURNALD_LOGGING
extern "C"
{
#include "log.c/log.h"
}

#define log_t(...) log_trace(__LINE__, __VA_ARGS__)
#define log_e(...) log_e(__LINE__, __VA_ARGS__)
#define log_w(...) log_warning(__LINE__, __VA_ARGS__)
#define log_i(...) log_info(__LINE__, __VA_ARGS__)
#else
#include <systemd/sd-journal.h>

#define log_t(...) sd_journal_print(1, __VA_ARGS__)
#define log_e(...) sd_journal_print(3, __VA_ARGS__)
#define log_w(...) sd_journal_print(4, __VA_ARGS__)
#define log_i(...) sd_journal_print(6, __VA_ARGS__)
#endif

char ERR_BUF[PCAP_ERRBUF_SIZE];

typedef void (*process_packet)(u_char *user, const struct pcap_pkthdr *h,
                               const u_char *bytes);

void handler(u_char *user, const struct pcap_pkthdr *h,
             const u_char *bytes);
int main(int, char **)
{
    if (pcap_init(PCAP_CHAR_ENC_UTF_8, ERR_BUF) != 0)
    {
        log_e(ERR_BUF);
        return -1;
    }

    // searching for interfaces
    pcap_if_t *device_list;
    if (pcap_findalldevs(&device_list, ERR_BUF) != 0)
    {
        log_e(ERR_BUF);
        return -1;
    }

    // choosing interface to listen
    do
    {
        if (strcmp(device_list->name, "eno1") == 0)
        {
            break;
        }
    } while (device_list = device_list->next);

    if (device_list == NULL)
    {
        log_e("No interface eno1");
        return -1;
    }

    // capturing object creating
    pcap_t *capture = pcap_create(device_list->name, ERR_BUF);

    if (capture == NULL)
    {
        log_e(ERR_BUF);
        pcap_freealldevs(device_list);
        return -1;
    }

    // erasing device_list
    pcap_freealldevs(device_list);


    // "all packets mode"
    if (pcap_set_promisc(capture, 1))
    {
        log_e(pcap_geterr(capture));
        pcap_close(capture);
        return -1;
    }

    // immediate mode (no delay between int and analysis)
    if (pcap_set_immediate_mode(capture, 1) != 0)
    {
        log_e(pcap_geterr(capture));
        pcap_close(capture);
        return -1;
    }

    // enabling capturing object
    if (pcap_activate(capture) != 0)
    {
        log_e(pcap_geterr(capture));
        pcap_close(capture);
        return -1;
    }

    // storing data in capture.pcap
    pcap_dumper_t *f_dumper = pcap_dump_open(capture, "capture.pcap");

    // endless capturing loop
    while (true)
    {
        pcap_pkthdr *p_head;
        const u_char *p_data;

        // analysis func calling (handler)
        pcap_dispatch(capture, 1, (process_packet)handler, (u_char *)f_dumper);
    }
}

// analysis func
void handler(u_char *user, const struct pcap_pkthdr *h,
             const u_char *packet)
{
    /* ethernet headers are always exactly 14 bytes */
    // writing packet to the file
    pcap_dump(user, h, packet);
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip;             /* The IP header */
    const struct sniff_tcp *tcp;           /* The TCP header */
    const u_char *payload;                 /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    // getting ethernet, ip, tcp headers from the packet 
    ethernet = (struct sniff_ethernet *)(packet);

    if (ethernet->ether_type != IP_TYPE)
    {
        log_w("Only IP packets can be handled 0x%08x\n", ethernet->ether_type);
        return;
    }

    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    if (size_ip < 20)
    {
        log_w("* Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    if (size_tcp < 20)
    {
        log_w("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    // getting payload from packet
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_src), src_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_str, INET_ADDRSTRLEN);

// throwing away 127.0.0.1 src and dst
/*
    if (!((strcmp(src_str, "127.0.0.1") == 0) || (strcmp(dst_str, "127.0.0.1") == 0)))
    {
        log_i("Packet captured From: %s To: %s", src_str, dst_str);
    }
*/
}
