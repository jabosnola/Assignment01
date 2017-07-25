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
	char *dev;

	//notice information that how to user//
	printf("You Can Capture The Packet.\n");
	printf("==============================================\n");
	printf("argv[1] : device info\n");
	printf("You must give argv[1]. (ex: ./pcap dum0)\n");
	//get device info - using default setting//
	if(argc != 2)
	{
		printf("Argument Error...You must restart...\n");
		return(2);
	}

	dev = argv[1];
	
	printf("Device: %s\n", dev);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	//get packet and analyze
	pcap(handle, header, packet);
	return (0);
}