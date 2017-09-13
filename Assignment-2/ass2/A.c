#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include<arpa/inet.h>

#define ETHER_ADDR_LEN 6

typedef struct __st_ethernet_header{
    u_char dest_addr[6];
    u_char src_addr[6];
    u_short type;
}ETH_HEAD;

void a_callback(u_char *,const struct pcap_pkthdr *,const u_char*);

u_char b_macaddr[6];
pcap_t* handle;

int main(int argc, char *argv[]){ 
    char *dev, s[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    unsigned int ar[6];
    int i;
    struct bpf_program fp;

    if(argc != 2){
	fprintf(stdout,"Usage: %s [Mac address of machineB]\n",argv[0]);
	return 0;
    }

    // Get Mac address of Machine B
    sscanf(argv[1], "%x:%x:%x:%x:%x:%x", ar, ar + 1, ar + 2, ar + 3, ar + 4, ar + 5);
    printf("B MAC address: ");
    for(i = 0;i < 6;i++){
	b_macaddr[i] = ar[i];
	printf("%02x%c", b_macaddr[i], i==5?'\n':':');
    }

    dev = pcap_lookupdev(s);
    if(dev == NULL){
	printf("pcap_lookupdev: %s\n",s);
	exit(1);
    }

    if(pcap_lookupnet(dev, &net, &mask, s) == -1){
	printf("Couldn't get netmask for device %s: %s\n", dev, s);
	exit(1);
    }

    handle = pcap_open_live(dev, BUFSIZ, 0, 0, s);
    if(handle == NULL){
	printf("pcap_open_live: %s\n",s);
	exit(1);
    }
    if(pcap_setdirection(handle,PCAP_D_OUT) != 0){
    	pcap_perror(handle, "set direction");
    	exit(1);
    }

    if(pcap_compile(handle, &fp, "icmp[icmptype] == icmp-echo", 0, net) != 0){
	pcap_perror(handle, "pcap_compile failed");
	exit(1);
    }
    if(pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "Couldn't install filter : %s\n", pcap_geterr(handle));
		exit(EXIT_FAILURE);
    }

    printf("Start listening\n");
    pcap_loop(handle, 0, a_callback, NULL);

    printf("\nMust NOT print\n");
    return 0;
}

void a_callback(u_char *user_args, const struct pcap_pkthdr* pkthdr, const u_char *packet){
    ETH_HEAD *eptr;
    int i;
    u_char *tosend;
    
    tosend = (u_char *)malloc(pkthdr->caplen);
    memcpy(tosend, packet, pkthdr->caplen);

    eptr = (ETH_HEAD *)tosend;
    
    printf("OLD: ");
    for(i = 0;i < 6;i++){
	printf("%02x%c", eptr->dest_addr[i], i==5?'\n':':');
    }
    memcpy(eptr->dest_addr, b_macaddr, 6);
    printf("NEW: ");
    for(i = 0;i < 6;i++){
	printf("%02x%c", eptr->dest_addr[i], i==5?'\n':':');
    }

    if(pcap_sendpacket(handle, tosend, pkthdr->caplen) != 0){
	pcap_perror(handle, "sendpacket fail");
	exit(1);
    }
}
