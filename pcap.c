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
	int data_loc;

	while(1)
	{
		status = pcap_next_ex(handle, &header, &packet);

		if(status < 1)
			continue; //error or being read or time out//

		printf("Capture the packet!!!\n");
		
		ether = (struct ether_header*)packet;

		//Use ether_ntoa_r for reentrant thread-safe//
		printf("S o u r c e MAC : %s\n", ether_ntoa_r(ether->ether_shost, buf));
		printf("Destination MAC : %s\n", ether_ntoa_r(ether->ether_dhost, buf));

		//printf("ether type : %x\n", ether->ether_type, buf);
		
		if(ntohs(ether->ether_type) != ETHERTYPE_IP) // To change system order
			//printf("IPv4\n");
			continue;
		//printf("%d\n", ETH_HLEN);
		ipv4 = (struct ip*)(packet + ETH_HLEN);

		printf("S o u r c e IP : %s\n", inet_ntoa(ipv4->ip_src));
		printf("Destination IP : %s\n", inet_ntoa(ipv4->ip_dst));

		if(ipv4->ip_p != IPPROTO_TCP)
			continue;

		tcp	= (struct tcphdr*)(packet + ETH_HLEN + 4 * ipv4->ip_hl);

		printf("S o u r c e Port : %d\n", ntohs(tcp->th_sport));
		printf("Destination Port : %d\n", ntohs(tcp->th_dport));

		data_loc = ETH_HLEN + 4 * ipv4->ip_hl + 4 * tcp->th_off; // Data located in after Ethernet header, IP header, TCP header(TCP offset)

		printf("< Data Part >\n");

		for(int i = data_loc; i<data_loc+10; i++)
		{
			printf("%02x ", packet[i]);
		}

		printf("\n");
		
	}
	return (0);
}