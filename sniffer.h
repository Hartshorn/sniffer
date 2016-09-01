#ifndef SNIFFER_H
#define SNIFFER_H



#include <stdio.h>
#include <winsock2.h>

//#pragma comment(lib, "ws2_32.lib")

#define SIO_RCVALL _WSAIOW(IOC_VENDOR, 1)





void start_sniffing(SOCKET sock);


void process_packet(unsigned char*, int);
void print_ip_header(unsigned char*, int);
void print_tcp_header(unsigned char*, int);
void print_udp_packet(unsigned char*, int);
void print_icmp_packet(unsigned char*, int);
void print_data(unsigned char*, int);

void convert_to_hex(char*, unsigned int);

/* the :4 defines the bit field width */
typedef struct ip_hdr
{
	unsigned char ip_header_len: 4;
	unsigned char ip_version: 4;
	unsigned char ip_tos; /* ip type of service */
	unsigned short ip_total_length;
	unsigned short ip_id;

	unsigned char ip_frag_offset: 5; /* fragment offset field */
	unsigned char ip_more_fragment: 1;
	unsigned char ip_dont_fragment: 1;
	unsigned char ip_reserved_zero: 1;

	unsigned char ip_frag_offset1; /* fragement offset */

	unsigned char ip_ttl; /* time to live */
	unsigned char ip_protocol; /* TCP UDP - Protocol field */
	unsigned short ip_checksum;
	unsigned int ip_srcaddr;
	unsigned int ip_destaddr;

} IPV4_HDR;












#endif
