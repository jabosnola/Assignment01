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
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr *header;
	const u_char *packet;

	//get device info - using default setting//
	dev = pcap_lookupdev(errbuf);
	
	if(dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);

	//get packet and analyze
	pcap(handle, header, packet);
}