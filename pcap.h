#ifndef __PCAP_H__
#define __PCAP_H__
void pcap(pcap_t *handle, struct pcap_pkthdr *header, const u_char *packet);
#endif
