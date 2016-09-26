#include "../include/sniffer.h"

int main(int argc, char** argv) {

    int tcp = 0, udp = 0, icmp = 0, igmp = 0, others = 0, total = 0, i, j;
    
    unsigned int res;
    unsigned char errbuf[PCAP_ERRBUF_SIZE], buffer[100];
    const u_char *pkt_data;
    char hex[2];
    pcap_if_t *alldevices, *device;
    pcap_t *fp;
    time_t seconds;
    const time_t tbreak;
    
    
    struct ethernet_header *ethhdr;
    struct pcap_pkthdr *header;
    
    device = interface_handler(alldevices, errbuf);
    
    if ((fp = pcap_open(device->name,
                                100,
                                PCAP_OPENFLAG_PROMISCUOUS,
                                20,
                                NULL,
                                errbuf)) == NULL) 
    {
        fprintf(stderr, "\nError opening adapter\n");
        return (EXIT_FAILURE);
    }
    
    int count = 0;
    while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
        
        if(res == 0) {
            continue;
        }
        
        fprintf(stdout, "\nres: %d\nusec: %ld\nlen : %ld\ncaplen: %ld", header->ts.tv_usec, header->len, header->caplen);
        
        fprintf(stdout, "\npkt_data: %s\n", pkt_data);
        
        if(count++ > 5) {
            return (EXIT_SUCCESS);
        }
        if(res == -1) {
            fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
            return (EXIT_FAILURE);
        }
        
    }

    
    
    return (EXIT_SUCCESS);
}


