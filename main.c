#include "sniffer.h"



int main(void)
{


	FILE *logfile;
	int tcp = 0;
	int udp = 0;
	int icmp = 0;
	int others = 0;
	int igmp = 0;
	int total = 0;

	int i, j;

	struct sockaddr_in source, dest;
	char hex[2];

	struct ipv4_header *ip_hdr;
	struct tcp_header  *tcp_hdr;
	struct udp_header  *udp_hdr;
	struct icmp_header *icmp_hdr;

	SOCKET sniffer;
	struct in_addr addr;
	int in;

	char hostname[100];
	struct hostent *local;
	WSADATA wsa;

	if ((logfile = fopen("sniffer.log", "w")) == NULL)
		printf("unable to create file");

	if (WSAStartup(MAKEWORD(3,2), &wsa) != 0) {

		printf("WSAStartup() failed.\n");
		return 1;
	}

	if ((sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == INVALID_SOCKET) {
		printf("Failed to create raw socket.\n");
		return 1;
	}










	
	closesocket(sniffer);
	
	return 0;

}
