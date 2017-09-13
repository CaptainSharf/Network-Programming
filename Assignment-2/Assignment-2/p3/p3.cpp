#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string>
#include <map>

#define SIZE_ETHERNET 14

using namespace std;

map<string,int> IP_stats;

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char*
    packet)
{
    static int count = 0; //Count for number of packets processed
    count++;
    pcap_t* p =(pcap_t*) args; //Typecasting packet handler
    const struct sniff_ip *ip; //Pointer for getting IP

    /*The packet contains three fields:
    1.Ethernet Field that contains:Ethernet Source and destination MAC Addresses
    2.IP Field which contains information given in the struct
    3.The Payload which contains the actual message
    The Size of the ETHERENET field is 14(6(src u_char)+6(dst u_char)+2(short)
    Thus we need to extract information relevant for IP as shown below
    */

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET); //Typecasting to IP
    const char *printable_ip = inet_ntoa(ip->ip_src); //Convert struct in_addr ip->ip_src to const char*
    string IP(printable_ip); //Convert char* to string for storing in a dictionary
    IP_stats[IP]++; //Increment count of packet related to a particular IP

    cout << "After " << count << " packets\n";
    for(map<string,int>::iterator it = IP_stats.begin(); it != IP_stats.end(); ++it)
        cout << it->first << ":" << it->second << "\n";
    cout << endl;
}

int main(int argc,char **argv)
{
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;    /* net/ethernet.h */
    struct bpf_program fp;        /* hold compiled program */
    bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */
 
    if(argc != 2){
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
 
    /* open device for reading in promiscuous mode */
    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf); //Creates a packet handler for reading packets on dev 
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }
    /* Capture packets going out of machine C returns 0 on success and -1 on a failure */
    int val  = pcap_setdirection(descr,PCAP_D_IN);
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
    /* loop for callback function and -1 loops infinitely*/
    pcap_loop(descr, -1, my_callback,(u_char *)descr);
    return 0;
}