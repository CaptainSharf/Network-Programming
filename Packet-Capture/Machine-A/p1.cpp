#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <string>
#include <map>
#define SIZE_ETHERNET 14
int length = 0;
char *dest_addr;
using namespace std;
/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dest_host[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_source_host[ETHER_ADDR_LEN];    /* source host address */
        u_short typ;                     /* IP? ARP? RARP? etc */
};

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char*
    packet)
{
    static int count = 0;
    count++;
    pcap_t* p =(pcap_t*) args; //Typecasting packet handler

    struct sniff_ethernet *ethernet;

    /* Get information from a packet regarding the ethernet */
     /*The packet contains three fields:
    1.Ethernet Field that contains:Ethernet Source and destination MAC Addresses
    2.IP Field which contains information given in the struct
    3.The Payload which contains the actual message
    The Size of the ETHERENET field is 14(6(src u_char)+6(dst u_char)+2(short)
    Thus we need to extract information relevant for IP as shown below
    */
    ethernet = (struct sniff_ethernet*)(packet);
    struct ether_addr *new_addr = ether_aton(dest_addr);
    uint8_t *temp = (uint8_t*) new_addr;

    memcpy(&ethernet->ether_dest_host,temp,sizeof(temp)+1);
    /* Convert changed dest address to char* for checking*/
    const char *test_str = ether_ntoa((const struct ether_addr *)&ethernet->ether_dest_host);
    /* convert to a new packet*/
    u_char *dup_packet1 = (u_char*) ethernet;
    /* Returns 0 if a packet is sent successfully */
    int val = pcap_sendpacket(p,dup_packet1,100);
    cout << val << endl;
}

int main(int argc,char **argv)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr hdr;
    pcap_t *descr;
    struct ether_header *eptr;    /* net/ethernet.h */
    struct bpf_program fp;        /* hold compiled program */
    bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */
 
    if(argc <2){
        fprintf(stdout, "Usage: %s \"expression\"\n"
            ,argv[0]);
        return 0;
    }

    /* Now get a device */
    dev = pcap_lookupdev(errbuf); //Get an interface for a device for reading
    
    if(dev == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }
        /* Get the network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);
    dest_addr = argv[2];
    /* open device for reading in promiscuous mode */
    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf); //Creates a packet handler for reading packets on dev
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }
    /* Capture packets going out of machine A returns 0 on success and -1 on a failure */
    int value  = pcap_setdirection(descr,PCAP_D_IN);
    /* argv[1] specifies what type of packets to process and we'll compile the filter expression */
    if(pcap_compile(descr, &fp, argv[1], 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }
 
    /* set the filter */
    if(pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }
    pcap_loop(descr, -1, my_callback,(u_char *)descr);
    return 0;
}