#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <sys/time.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <errno.h>

int errno;

#define VERBOSE (0)
#define MAXBUFSIZE (2048)
#define ICMP_DATA_SIZE (64 - sizeof(struct icmphdr))

typedef struct raw_icmp_packet {
	struct iphdr ip_hdr;
	struct icmphdr icmp_hdr;
	unsigned char data[ICMP_DATA_SIZE];
} raw_icmp_packet_t;

typedef struct icmp_send_return {
	char* incoming;
	int incoming_size;
	struct sockaddr_in* dest_addr;
} icmp_send_return_t;

unsigned short calc_chksum(void* buf, size_t len)
{
	unsigned short* ptr = (unsigned short*)buf;

	unsigned int chksum = 0;

	int remaining;

	for (remaining = len; remaining > 1; remaining -= 2) {
		chksum += *ptr++;
	}

	if (remaining == 1) {
		chksum += *(unsigned char*)ptr;
	}

	chksum = (chksum >> 16) + (chksum & 0xffff);
	chksum += (chksum >> 16);

	return ~chksum;
}

int set_timeout(int sock_fd, int timeout_ms)
{
	int secs = timeout_ms / 1000;
	int usecs = (timeout_ms - (secs * 1000)) * 1000;
	
	struct timeval tv = {0};

	tv.tv_sec = secs;
	tv.tv_usec = usecs;

	return setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

void set_ttl(raw_icmp_packet_t* pkt, int ttl)
{
	pkt->ip_hdr.ttl = ttl;
}

int set_hdrincl(int sock_fd)
{
	int on = 1;

	return setsockopt(sock_fd, SOL_IP, IP_HDRINCL, &on, sizeof(on));
}

int verify_incoming_packet(raw_icmp_packet_t* sent, char* received, int recvcount, struct sockaddr_in* dest_addr)
{
	int result = 0;

	struct iphdr* ip_hdr = (struct iphdr*)received;

	struct icmphdr* icmp_hdr = (struct icmphdr*)(received + ip_hdr->ihl * 4);

	if (icmp_hdr->type == ICMP_TIME_EXCEEDED) {
		struct iphdr* ip_hdr_inner = (struct iphdr*)((char*)icmp_hdr + sizeof(struct icmphdr));

		struct icmphdr* icmp_hdr_inner = (struct icmphdr*)((char*)ip_hdr_inner + ip_hdr_inner->ihl * 4);

		if (icmp_hdr_inner->un.echo.id == sent->icmp_hdr.un.echo.id &&
			icmp_hdr_inner->un.echo.sequence == sent->icmp_hdr.un.echo.sequence)
		{
			result = 1;
		}
	} if (icmp_hdr->type == ICMP_ECHOREPLY) {
		if (icmp_hdr->un.echo.id == sent->icmp_hdr.un.echo.id &&
			icmp_hdr->un.echo.sequence == sent->icmp_hdr.un.echo.sequence)
		{
			result = 1;
		}
	}

	return result;
}

void init_ip_hdr(raw_icmp_packet_t* pkt, const char* src_ip, const char* dest_ip)
{
	pkt->ip_hdr.ihl = sizeof(struct iphdr) / 4;
	pkt->ip_hdr.version = 4;
	pkt->ip_hdr.tos = 0;
	pkt->ip_hdr.tot_len = htons(sizeof(raw_icmp_packet_t));
	pkt->ip_hdr.id = htons(getpid());
	pkt->ip_hdr.frag_off = 0;
	pkt->ip_hdr.ttl = 64;
	pkt->ip_hdr.protocol = IPPROTO_ICMP;
	pkt->ip_hdr.check = 0;
	pkt->ip_hdr.saddr = inet_addr(src_ip);
	pkt->ip_hdr.daddr = inet_addr(dest_ip);

	pkt->ip_hdr.check = calc_chksum((void*)pkt, sizeof(struct iphdr));
}

void init_icmp_hdr(raw_icmp_packet_t* pkt)
{
	pkt->icmp_hdr.type = ICMP_ECHO;
	pkt->icmp_hdr.un.echo.id = htons(getpid());
	pkt->icmp_hdr.un.echo.sequence = htons(1);
	
	int idx;
	for (idx = 0; idx < ICMP_DATA_SIZE - 1; idx++) {
		pkt->data[idx] = (char)('0' + idx);
	}

	pkt->data[ICMP_DATA_SIZE - 1] = '\0';

	pkt->icmp_hdr.checksum = 0;
	pkt->icmp_hdr.checksum = calc_chksum((void*)((char*)pkt + sizeof(pkt->ip_hdr)), sizeof(pkt->icmp_hdr) + sizeof(pkt->data));
}

const char* get_local_ip_address(int sock_fd, const char* interface)
{
	struct ifreq ifr;

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	ioctl(sock_fd, SIOCGIFADDR, &ifr);

	char* ip_addr = malloc(INET_ADDRSTRLEN);

	memset(ip_addr, 0, INET_ADDRSTRLEN);

	inet_ntop(AF_INET, &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr, ip_addr, INET_ADDRSTRLEN);

	return ip_addr;
}

const char* get_ip_addr_for_hostname(const char* name)
{
	char* ip_addr = malloc(INET_ADDRSTRLEN);
	memset(ip_addr, 0, INET_ADDRSTRLEN);

	struct addrinfo* info = NULL;

	struct addrinfo hints = { 0 };
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;

	getaddrinfo(name, NULL, &hints, &info);

	if(info) {
		inet_ntop(AF_INET, &((struct sockaddr_in*)info->ai_addr)->sin_addr, ip_addr, INET_ADDRSTRLEN);
		freeaddrinfo(info);
	} else {
		free(ip_addr);
		ip_addr = NULL;
	}

	return (const char*)ip_addr;
}

void init_dest_addr(const char* ip_addr, struct sockaddr_in* dest_addr)
{
	dest_addr->sin_family = AF_INET;
	dest_addr->sin_port = htons(0);

	if (inet_pton(AF_INET, ip_addr, &dest_addr->sin_addr) < 0) {
		perror("[ERROR] inet_pton failed");
	}
}

icmp_send_return_t* send_icmp_packet(int ttl, const char* local_ip_addr, const char* dest_ip_addr)
{
	int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	int recv_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (sock_fd < 0) {
		perror("[ERROR] couldn't create socket");
		return NULL;
	}

	if ( set_timeout(recv_sock_fd, 500) < 0 ) {
		perror("[ERROR] Couldn't set receive timeout sockopt");
		close(sock_fd);
		close(recv_sock_fd);
		return NULL;
	}

	if ( set_hdrincl(sock_fd) < 0 ) {
		perror("[ERROR] Couldn't set IP_HDRINCL sockopt");
		close(sock_fd);
		close(recv_sock_fd);
		return NULL;
	}

	raw_icmp_packet_t* pkt = malloc(sizeof(raw_icmp_packet_t));
	memset(pkt, 0, sizeof(raw_icmp_packet_t));

	struct sockaddr_in* dest_addr = malloc(sizeof(struct sockaddr_in));
	memset(dest_addr, 0, sizeof(struct sockaddr_in));

	init_dest_addr(dest_ip_addr, dest_addr);

	init_ip_hdr(pkt, local_ip_addr, dest_ip_addr);

	set_ttl(pkt, ttl);

	init_icmp_hdr(pkt);

	int bytes = sendto(sock_fd, pkt, sizeof(raw_icmp_packet_t), 0, (struct sockaddr*)dest_addr, sizeof(*dest_addr));

	if ( bytes < 0 ) {
		perror("[ERROR] sendto failed");
		close(sock_fd);
		close(recv_sock_fd);
		free(pkt);
		return NULL;
	} else {
		if (VERBOSE) {
			printf("[INFO] sendto: Sent %d bytes.\n", bytes);
		}
	}

	char* buf = malloc(MAXBUFSIZE);
	memset(buf, 0, MAXBUFSIZE);

	socklen_t dest_addr_socklen = sizeof(*dest_addr);
	bytes = recvfrom(recv_sock_fd, buf, MAXBUFSIZE, 0, (struct sockaddr*)dest_addr, &dest_addr_socklen);

	if (bytes < 0) {

		icmp_send_return_t* ret = NULL;

		if (errno != EAGAIN) {
			perror("[ERROR] recvfrom failed");
		} else {
			ret = malloc(sizeof(icmp_send_return_t));
			ret->incoming = NULL;
			ret->incoming_size = 0;
			ret->dest_addr = NULL;
		}

		free(pkt);
		close(sock_fd);
		close(recv_sock_fd);

		return ret;
	} else {
		if (VERBOSE) {
			printf("[INFO] recvfrom: Received %d bytes, sock_len %d\n", bytes, dest_addr_socklen);
		}
	}

	if (verify_incoming_packet(pkt, buf, bytes, dest_addr)) {
		close(sock_fd);
		close(recv_sock_fd);
		free(pkt);

		icmp_send_return_t* ret = malloc(sizeof(icmp_send_return_t));

		ret->incoming = buf;
		ret->incoming_size = bytes;
		ret->dest_addr = dest_addr;

		return ret;
	} else {
		close(sock_fd);
		close(recv_sock_fd);
		free(buf);
		free(pkt);
		return NULL;
	}
}

char* reverse_dns(struct sockaddr* sock_addr)
{
	char* result = NULL;

	char* host = malloc(256);
	memset(host, 0, 256);

	if( getnameinfo(sock_addr, sizeof(*sock_addr), host, 256, NULL, 0, 0) < 0) {
		perror("[ERROR] getnameinfo failed");
		free(host);
	} else {
		result = host;
	}

	return result;
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <hostname>\n", argv[0]);
		return 1;
	}

	int ttl = 1;
	icmp_send_return_t* recv = NULL;

	int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	char interface[] = "enx00e04c6806a0";
	const char* local_ip_addr = get_local_ip_address(sock_fd, interface);
	printf("[INFO] Local IP from interface %s: %s\n", interface, local_ip_addr);

	close(sock_fd);

	const char* dest_ip_addr = get_ip_addr_for_hostname(argv[1]);

	if (!dest_ip_addr) {
		fprintf(stderr, "[ERROR] hostname couldn't be resolved\n");
	} else {
		printf("[INFO] Host %s resolved to %s\n", argv[1], dest_ip_addr);

		char ip_addr[INET_ADDRSTRLEN] = { 0 };

		do {
			recv = send_icmp_packet(ttl, local_ip_addr, dest_ip_addr);

			if (recv) {
				if (recv->dest_addr) {
					inet_ntop(AF_INET, &recv->dest_addr->sin_addr, ip_addr, INET_ADDRSTRLEN);

					char* rdns_result = reverse_dns((struct sockaddr*)recv->dest_addr);

					if (rdns_result) {
						printf("%4d\t%s\t(%s)\n", ttl, rdns_result, ip_addr);
						free(rdns_result);
					} else {
						printf("%4d\t(FAILED RDNS)\t(%s)\n", ttl, ip_addr);
					}

				} else {
					printf("%4d\t* * *\n", ttl);
				}

				if (recv->incoming)
					free(recv->incoming);

				if (recv->dest_addr)
					free(recv->dest_addr);

				free(recv);

				ttl++;
			}
		} while(strncmp(dest_ip_addr, ip_addr, INET_ADDRSTRLEN) && ttl < 31);

		free((char*)dest_ip_addr);
	}

	free((char*)local_ip_addr);

	return 0;
}
