#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "pcap.h"

void pcap(pcap_t *handle, struct pcap_pkthdr *header, const u_char *packet)
{
	int status;
	struct ether_header *ether;
	char buf[1000];

	while(1)
	{
		status = pcap_next_ex(handle, &header, &packet);

		if(status < 1)
			continue; //error or being read or time out//

		printf("Capture the packet!!!\n");
		
		ether = (struct ether_header*)packet;

		//Use ether_ntoa_r for reentrant thread-safe//
		printf("S o u r c e  MAC : %s\n", ether_ntoa_r(ether->ether_shost, buf));
		printf("Destionation MAC : %s\n", ether_ntoa_r(ether->ether_dhost, buf));

		//printf("ether type : %x\n", ether->ether_type, buf);
		
		if(ntohs(ether->ether_type) != ETHERTYPE_IP)
			//printf("IPv4\n");
			continue;

		
		
	}
	
}