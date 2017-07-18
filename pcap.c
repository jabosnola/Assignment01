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
	struct ip *ipv4;
	struct tcphdr *tcp;
	int i = 1;
	int len;

	printf("-------------------------------------------------\n\n");
	while(1)
	{
		status = pcap_next_ex(handle, &header, &packet);

		if(status < 1)
			continue; //error or being read or time out//

		printf("-------------------------------------------------\n\n");
		printf("No.%02d Packet captured!!!\n\n", i);
		i++;

		ether = (struct ether_header*)packet;

		//Use ether_ntoa_r for reentrant thread-safe//
		printf("S o u r c e MAC : %s\n", ether_ntoa_r(ether->ether_shost, buf));
		printf("Destination MAC : %s\n\n", ether_ntoa_r(ether->ether_dhost, buf));
		
		if(ntohs(ether->ether_type) != ETHERTYPE_IP) // To change system order
			continue;
		
		ipv4 = (struct ip*)(packet + ETH_HLEN);

		printf("S o u r c e IP : %s\n", inet_ntop(AF_INET, &ipv4->ip_src, buf, sizeof(buf)));
		printf("Destination IP : %s\n\n", inet_ntop(AF_INET, &ipv4->ip_dst, buf, sizeof(buf)));

		if(ipv4->ip_p != IPPROTO_TCP)
			continue;

		tcp	= (struct tcphdr*)(packet + ETH_HLEN + 4 * ipv4->ip_hl);

		printf("S o u r c e Port : %d\n", ntohs(tcp->th_sport));
		printf("Destination Port : %d\n\n", ntohs(tcp->th_dport));

		//printf("ip len : %d", ntohs(ipv4->ip_len));
		len = ntohs(ipv4->ip_len) - (4 * ipv4->ip_hl + 4 * tcp->th_off);

		printf("< Data Part >\n");

		if(len > 10)
		{
			for(int i = 0; i<10; i++)
				printf("%02x ", packet[i+ETH_HLEN+4 * ipv4->ip_hl + 4 * tcp->th_off]);
		}
		else if(len == 0)
			printf("No Data\n");
		else
		{
			for(int i = 0; i<len; i++)
				printf("%02x ", packet[i+ETH_HLEN+4 * ipv4->ip_hl + 4 * tcp->th_off]);
		}

		printf("\n\n");
		printf("-------------------------------------------------\n\n");
	}
	return (0);
}