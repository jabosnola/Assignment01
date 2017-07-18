#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "pcap.h"

int main(int argc, char *argv[])
{
	char  errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr *header;
	const u_char *packet;
	int status;
	struct ether_header *ether;
	char buf[1000];
	struct ip *ipv4;
	struct tcphdr *tcp;
	int data_loc;
	char *dum0;

	//get device info - using default setting//
	dum0 = pcap_lookupdev(errbuf);
	
	if(dum0 == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dum0);

	handle = pcap_open_live(dum0, BUFSIZ, 1, 1000, errbuf);

	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	//printf("Device: %s\n", 'dum0');

	//get packet and analyze
	pcap(handle, header, packet);
	return (0);
}