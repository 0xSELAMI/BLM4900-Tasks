#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>

#define NTP_PORT            123     // Local port to listen for UDP packets
#define NTP_PACKET_SIZE     48      // NTP time stamp is in the first 48 bytes of the message

typedef unsigned long long tstamp;

// Buffer to hold outgoing packets.
unsigned char ntpRequest [NTP_PACKET_SIZE];

typedef struct ntp_timestamp {
	uint32_t secs;
	uint32_t frac;
} ntp_timestamp_t;

typedef struct ntp_header {
	uint8_t mode:           3;
	uint8_t version_number: 3;
	uint8_t leap_indicator: 2;

	/* uint32_t stratum:        8; */
	/* uint32_t poll:           8; */
	/* uint32_t precision:      8; */
	// somehow me changing this order doesnt seem to matter, im not sure why
	int8_t precision;
	int8_t poll;
	uint8_t stratum;
} ntp_header_t;

typedef struct ntp_packet {
	ntp_header_t hdr;

	uint32_t root_delay;
	uint32_t root_dispersion;
	unsigned char ref_identifier[4];

	ntp_timestamp_t ref_timestamp;
	ntp_timestamp_t org_timestamp;
	ntp_timestamp_t rec_timestamp;
	ntp_timestamp_t xmt_timestamp;
	
} ntp_packet_t;

// Function to prepare an NTP request
// You should fill this out 
void createNtpRequest ( ntp_packet_t* ntpRequest ) {

    // Set all bytes in the buffer to 0.
    memset (ntpRequest, 0, NTP_PACKET_SIZE);

    // Initialize values needed to form NTP request
	ntpRequest->hdr.leap_indicator = 0x3;
	ntpRequest->hdr.version_number = 0x4;
	ntpRequest->hdr.mode           = 0x3;

	ntpRequest->hdr.stratum        = 0x0;
	ntpRequest->hdr.poll           = 0x6;
	ntpRequest->hdr.precision      = 0xEC;

	// NIST but backwards
	strncpy(ntpRequest->ref_identifier, "TSIN", 4);

	// timestamps are already initialized with zero, along with root_delay and root_dispersion
}

void ntp_timestamp_to_timeval(struct timeval* tv, tstamp ntp_ts)
{
	uint64_t secdiff = (70 * 365 + 17);
	secdiff *= 86400;

	uint64_t usecs = (ntp_ts << 32) >> 32;
	usecs *= 1000000;
	usecs >>= 32;

	tv->tv_sec = (ntp_ts >> 32) - secdiff;
	tv->tv_usec = usecs;
}

tstamp ntoh_timestamp(ntp_timestamp_t ntp_ts)
{
	uint64_t secs = ntohl(ntp_ts.secs);
	uint64_t frac = ntohl(ntp_ts.frac);

	return (secs << 32) | frac;
}

void pretty_print_timeval(const char* tstype, struct timeval* tv)
{
	char timestr[20] = { 0 };
	struct tm* tmp = localtime(&tv->tv_sec);

	if (tmp == NULL) {
		perror("localtime");
	}

	strftime(timestr, sizeof(timestr), "%Y/%m/%d %H:%M:%S", tmp);

	printf("%-21s %s.%06ld\n", tstype, timestr, tv->tv_usec);
}

void hexdump_response(const unsigned char* ntpResponse)
{
	int i, j = 0;

	for(i = 0; i < 8; i++) {
		printf("%-4d ", i);
	}
	printf("\n");

	for(i = 0; i < NTP_PACKET_SIZE; i++) {
		printf("0x%02x ", ntpResponse[i]);
		if (++j >= 8) {
			printf("\n");
			j = 0;
		};
	}
	printf("\n");
}

int main()  {

	int n, s, socSize;
	char  *hostname = "162.159.200.123";

	unsigned char ntpResponse[NTP_PACKET_SIZE] = { 0 };
	ntp_packet_t ntpRequest = { 0 };

	struct sockaddr_in server_addr;
	struct sockaddr_in source_addr;

	s=socket(AF_INET, SOCK_DGRAM, 0);
	if(s<0) {
		perror("ERR>> Can not create socket");
	}

	memset( &source_addr, 0, sizeof( source_addr ));
	/* source_addr.sin_family=AF_INET; */
	/* source_addr.sin_addr.s_addr = INADDR_ANY; */
	/* source_addr.sin_port=htons(NTP_PORT); */

	memset( &server_addr, 0, sizeof( server_addr ));
	server_addr.sin_family=AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(hostname);
	server_addr.sin_port=htons(NTP_PORT);

	createNtpRequest(&ntpRequest);
	n = sendto(s, (unsigned char*)&ntpRequest, sizeof(ntpRequest),0,(struct sockaddr *)&server_addr, sizeof(server_addr));

	if (n < 0) {
		perror("sendto failed");
	} else {
		printf("request sent %d byte(s), waiting for a reply...\n", n);
	}

	socklen_t source_socklen = sizeof(source_addr);

	// Receiving a reply
	n = recvfrom(s, ntpResponse, sizeof(ntpResponse), 0, (struct sockaddr*)&source_addr, &source_socklen);

	if (n < 0) {
		perror("recvfrom failed");
		exit(1);
	}

	printf("response received %d byte(s)...\n\n", n);
	hexdump_response(ntpResponse);

	// Now you have to process it 
	struct timeval ref_ts = { 0 };
	struct timeval rec_ts = { 0 };
	struct timeval xmt_ts = { 0 };

	tstamp ref_timestamp = ntoh_timestamp(((ntp_packet_t*)ntpResponse)->ref_timestamp);
	tstamp rec_timestamp = ntoh_timestamp(((ntp_packet_t*)ntpResponse)->rec_timestamp);
	tstamp xmt_timestamp = ntoh_timestamp(((ntp_packet_t*)ntpResponse)->xmt_timestamp);

	ntp_timestamp_to_timeval(&ref_ts, ref_timestamp);
	ntp_timestamp_to_timeval(&rec_ts, rec_timestamp);
	ntp_timestamp_to_timeval(&xmt_ts, xmt_timestamp);

	// Print out time 
	pretty_print_timeval("[REFERENCE TIMESTAMP]", &ref_ts);
	pretty_print_timeval("[RECEIVE TIMESTAMP]", &rec_ts);
	pretty_print_timeval("[TRANSMIT TIMESTAMP]", &xmt_ts);

	return 0;
}

