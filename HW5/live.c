#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

#include <stdlib.h>
#include <string.h>

#define TYPESTRLEN 64

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

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
            char tmbuf[64], buf[64];

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
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */

    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    printf("INTERFACE: %s\n\n", device);

    /* Open device for live capture */
    handle = pcap_open_live(
            device,
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            error_buffer
    );

    if (handle == NULL) {
        printf("ERROR: %s\n", error_buffer);
        exit(1);
    }

    u_char* user = NULL;
    pcap_loop(handle, 0, callback, user);

    return 0;
}
