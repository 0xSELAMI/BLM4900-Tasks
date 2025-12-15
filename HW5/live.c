#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <pcap.h>

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

//#include <stdlib.h>
#define UNUSED(x) (void)(x)

#define TYPESTRLEN 64

void icmp_type_to_str(unsigned int type, char* icmp_type_string)
{
    switch (type) {
        case ICMP_ECHOREPLY:
            strncpy(icmp_type_string, "ICMP_ECHOREPLY", TYPESTRLEN);
            break;
        case ICMP_DEST_UNREACH:
            strncpy(icmp_type_string, "ICMP_DEST_UNREACH", TYPESTRLEN);
            break;
        case ICMP_SOURCE_QUENCH:
            strncpy(icmp_type_string, "ICMP_SOURCE_QUENCH", TYPESTRLEN);
            break;
        case ICMP_REDIRECT:
            strncpy(icmp_type_string, "ICMP_REDIRECT", TYPESTRLEN);
            break;
        case ICMP_ECHO:
            strncpy(icmp_type_string, "ICMP_ECHO", TYPESTRLEN);
            break;
        case ICMP_TIME_EXCEEDED:
            strncpy(icmp_type_string, "ICMP_TIME_EXCEEDED", TYPESTRLEN);
            break;
        case ICMP_PARAMETERPROB:
            strncpy(icmp_type_string, "ICMP_PARAMETERPROB", TYPESTRLEN);
            break;
        case ICMP_TIMESTAMP:
            strncpy(icmp_type_string, "ICMP_TIMESTAMP", TYPESTRLEN);
            break;
        case ICMP_TIMESTAMPREPLY:
            strncpy(icmp_type_string, "ICMP_TIMESTAMPREPLY", TYPESTRLEN);
            break;
        case ICMP_INFO_REQUEST:
            strncpy(icmp_type_string, "ICMP_INFO_REQUEST", TYPESTRLEN);
            break;
        case ICMP_INFO_REPLY:
            strncpy(icmp_type_string, "ICMP_INFO_REPLY", TYPESTRLEN);
            break;
        case ICMP_ADDRESS:
            strncpy(icmp_type_string, "ICMP_ADDRESS", TYPESTRLEN);
            break;
        case ICMP_ADDRESSREPLY:
            strncpy(icmp_type_string, "ICMP_ADDRESSREPLY", TYPESTRLEN);
            break;
        default:
            snprintf(icmp_type_string, TYPESTRLEN, "%d", type);
            break;
    }
}

void callback(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet)
{
    UNUSED(args);

    struct ether_header* eth_header = (struct ether_header*)packet;
    static unsigned int count = 1;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        //printf("IP Packet captured\n");
        struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));

        bool is_icmp = (ip_header->protocol == IPPROTO_ICMP);

        if (is_icmp) {
            char icmp_type_string[TYPESTRLEN] = { 0 };

            struct in_addr ip_addr;

            printf("ICMP Packet Captured! Count: %d\n", count++);
            printf("Packet capture length: %d\n", packet_header->caplen);
            printf("Packet total length %d\n", packet_header->len);

            time_t nowtime;
            struct tm *nowtm;
            char tmbuf[32], buf[40];

            nowtime = packet_header->ts.tv_sec;
            nowtm = localtime(&nowtime);
            strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
            snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, packet_header->ts.tv_usec);
            printf("Time : %s\n", buf);

            ip_addr.s_addr = ip_header->saddr;

            printf("Source: %s\n", inet_ntoa(ip_addr));

            ip_addr.s_addr = ip_header->daddr;

            printf("Destination: %s\n", inet_ntoa(ip_addr));
            struct icmphdr* icmp_header = (struct icmphdr*)(((unsigned char*)ip_header) + (ip_header->ihl * 4));
            icmp_type_to_str(icmp_header->type, icmp_type_string);

            printf("Type: %s\n\n", icmp_type_string);
        }
    }
}

int main(int argc, char *argv[]) {
    UNUSED(argc); UNUSED(argv);

    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevsp = NULL;
    pcap_t *handle      = NULL;
    int promisc_mode    = 1;
    int timeout_limit   = 1000; /* In milliseconds */

    if (pcap_findalldevs(&alldevsp, error_buffer) < 0) {
        fprintf(stderr, "pcap_findalldevs() : %s\n", error_buffer);
        return 1;
    } else if (alldevsp == NULL) {
        fprintf(stderr, "pcap_findalldevs() : no devices found\n");
        return 1;
    }

    device = alldevsp->name;

    printf("INTERFACE: %s\n\n", device);

    /* Open device for live capture */
    handle = pcap_open_live(
            device,
            BUFSIZ,
            promisc_mode,
            timeout_limit,
            error_buffer
    );

    if (handle == NULL) {
        printf("ERROR: %s\n", error_buffer);
        return 1;
    }

    u_char* user = NULL;
    pcap_loop(handle, 0, callback, user);

    return 0;
}
