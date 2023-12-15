#include <iostream>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <grpcpp/grpcpp.h>
#include "src/grpc_sender/grpc_sender.h"

#include "include/ip.h"
#include "include/errors.h"

#include "src/detector/detector.hpp"
#include "src/console_sender/console_sender.hpp"



//#define JOURNALD_LOGGING

#ifndef JOURNALD_LOGGING
extern "C"
{
    #include "src/log.c/log.h"
}

#define log_t(...) log_trace(__VA_ARGS__)
#define log_e(...) log_error(__VA_ARGS__)
#define log_w(...) log_warn(__VA_ARGS__)
#define log_i(...) log_info(__VA_ARGS__)

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
int main(int argc, char ** argv)
{  

    int opt;

    std::string interface_name;
    std::string rule_path;
    std::string grpc_host;

    while ((opt = getopt(argc, argv, "i:r:h:")) != -1) {
        switch (opt)
        {
        case 'i':
            interface_name = optarg;
            break;
        case 'r':
            rule_path = optarg;
            break;
        case 'h':
            grpc_host = optarg;
            break;

        default:
            break;
        }
    }
    
    if (interface_name.empty() || rule_path.empty() || grpc_host.empty()) {
        printf("Usage: libpcap-demo -i [interface] -r [yara rule] -h [grpc host]\n");
        return 0;
    }

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, ERR_BUF) != 0)
    {
        log_e(ERR_BUF);
        return -1;
    }

    pcap_if_t *device_list;
    if (pcap_findalldevs(&device_list, ERR_BUF) != 0)
    {
        log_e(ERR_BUF);
        return -1;
    }

    do
    {
        if (strcmp(device_list->name, interface_name.c_str()) == 0)
        {
            break;
        }
    } while ((device_list = device_list->next));

    if (device_list == NULL)
    {
        log_e("No interface %s", interface_name.c_str());
        return -1;
    }

    pcap_t *capture = pcap_create(device_list->name, ERR_BUF);

    if (capture == NULL)
    {
        log_e(ERR_BUF);
        pcap_freealldevs(device_list);
        return -1;
    }

    pcap_freealldevs(device_list);

    if (pcap_set_promisc(capture, 1))
    {
        log_e(pcap_geterr(capture));
        pcap_close(capture);
        return -1;
    }

    if (pcap_set_immediate_mode(capture, 1) != 0)
    {
        log_e(pcap_geterr(capture));
        pcap_close(capture);
        return -1;
    }

    if (pcap_activate(capture) != 0)
    {
        log_e(pcap_geterr(capture));
        pcap_close(capture);
        return -1;
    }

    log_i("Start detector creation");
    //pcap_dumper_t *f_dumper = pcap_dump_open(capture, "capture.pcap");
    FILE* yara_rules = fopen(rule_path.c_str(), "r");

    if (yara_rules == NULL) {
        log_e("Cant find rules at %s", rule_path.c_str());
        return D_ERR_YARA_FILE;
    }
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));

    std::string file_path = std::string(rule_path.c_str());
    std::string dir_path = file_path.substr(0, file_path.find_last_of("\\/"));
     
    chdir(dir_path.c_str());
    //ConsoleSender s =  ConsoleSender();
    const auto creds = grpc::InsecureChannelCredentials();
    GrpcSender s(grpc::CreateChannel(grpc_host.c_str(), creds));
    Detector d(&s, yara_rules);
    chdir(cwd);

    log_i("Main loop started");

    while (true)
    {
        pcap_pkthdr *p_head;
        const u_char *p_data;

        pcap_dispatch(capture, 1, (process_packet)handler, (u_char *)&d);
    }
}

void handler(u_char *user, const struct pcap_pkthdr *h,
             const u_char *packet)
{
    /* ethernet headers are always exactly 14 bytes */
    //pcap_dump(user, h, packet);
    Detector* d = (Detector*)user;
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip;             /* The IP header */
    const struct sniff_tcp *tcp;           /* The TCP header */
    const u_char *payload;                 /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    ethernet = (struct sniff_ethernet *)(packet);

    if (ethernet->ether_type != IP_TYPE)
    {
        //log_w("Only IP packets can be handled 0x%08x\n", ethernet->ether_type);
        return;
    }

    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;

    if (size_ip < 20)
    {
        //log_w("* Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    if (size_tcp < 20)
    {
        //log_w("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_src), src_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_str, INET_ADDRSTRLEN);

    //if (!((strcmp(src_str, "192.168.203.1") == 0) || (strcmp(dst_str, "192.168.203.1") == 0)))
    //{
    //    log_i("Packet captured From: %s To: %s", src_str, dst_str);
    //}
    //log_i("before Check payload");
    d->check_tcp_payload(payload, h->len - (SIZE_ETHERNET + size_ip + size_tcp), src_str, dst_str);
    //log_i("after Check payload");
}