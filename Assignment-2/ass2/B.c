#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6

typedef struct __st_ll{
    struct in_addr ip;
    u_char addr[6];
    int id;
    struct __st_ll *next;
}LL;

typedef struct __st_ethernet_header{
    u_char dest_addr[6];
    u_char src_addr[6];
    u_short type;
}ETH_HEAD;

typedef struct __st_ip_header{
    u_char verno_hlen;  // 4 bits version number, 4 bits (header length)/4
    u_char tos;
    u_short len;
    u_short id;
    u_short offset;
    u_char ttl;
    u_char proto;
    u_short chk_sum;
    struct in_addr src_addr, dest_addr;
}IP_HEAD;

typedef struct __st_icmp_header{
    u_char type;
    u_char code;
    u_short chk_sum;
    int id_seqnum;
}ICMP_HEAD;

void b_callback(u_char *,const struct pcap_pkthdr *,const u_char*);
void ll_insert(LL **, struct in_addr, u_char [6], int);
LL* ll_find(LL *, int);


u_char c_macaddr[6], b_macaddr[6];
struct in_addr c_ip, b_ip;
pcap_t* handle;
LL *ping_list;

int main(int argc, char *argv[]){ 
    char *dev, s[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    unsigned int ar[6];
    int i;
    struct bpf_program fp;

    if(argc != 3){
	fprintf(stdout,"Usage: %s [MAC of machineC] [IP of machineC]\n",argv[0]);
	return 0;
    }

    // Get Mac and IP of Machines C
    sscanf(argv[1], "%x:%x:%x:%x:%x:%x", ar, ar + 1, ar + 2, ar + 3, ar + 4, ar + 5);
    printf("C MAC address: ");
    for(i = 0;i < 6;i++){
	c_macaddr[i] = ar[i];
	printf("%02x%c", c_macaddr[i], i==5?'\n':':');
    }

    if(inet_aton(argv[2], &c_ip) == 0){
	printf("Error inet_aton %s\n", argv[2]);
	exit(1);
    }
    printf("C IP address: %s\n", inet_ntoa(c_ip));

    inet_aton("10.1.35.159", &b_ip);

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
    if(pcap_setdirection(handle,PCAP_D_IN) != 0){
    	pcap_perror(handle, "set direction");
    	exit(1);
    }

    if(pcap_compile(handle, &fp, "icmp[icmptype] == icmp-echo || icmp[icmptype] == icmp-echoreply", 0, net) != 0){
	pcap_perror(handle, "pcap_compile failed");
	exit(1);
    }
    if(pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "Couldn't install filter : %s\n", pcap_geterr(handle));
		exit(EXIT_FAILURE);
    }

    ping_list = NULL;
    printf("Start listening\n");
    pcap_loop(handle, 0, b_callback, NULL);

    printf("\nMust NOT print\n");
    return 0;
}

void b_callback(u_char *user_args, const struct pcap_pkthdr* pkthdr, const u_char *packet){
    ETH_HEAD *eptr;
    IP_HEAD *iptr;
    ICMP_HEAD *cptr;
    //    int i;
    u_char *tosend;
    LL *tmp;
    
    tosend = (u_char *)malloc(pkthdr->caplen);
    memcpy(tosend, packet, pkthdr->caplen);

    eptr = (ETH_HEAD *)tosend;
    iptr = (IP_HEAD *)(tosend + 14);
    cptr = (ICMP_HEAD *)(tosend + 14 + (iptr->verno_hlen & 15)*4);

    printf("from %s ", inet_ntoa(iptr->src_addr));
    printf("to %s\n", inet_ntoa(iptr->dest_addr));
    printf("type: %d id: %d\n", cptr->type, cptr->id_seqnum);

    if(cptr->type == 8){
	// From A
	ll_insert(&ping_list, iptr->src_addr, eptr->src_addr, cptr->id_seqnum);
	memcpy(b_macaddr, eptr->dest_addr, 6);

	// forward to C
	memcpy(eptr->src_addr, b_macaddr, 6);
	memcpy(eptr->dest_addr, c_macaddr, 6);
	iptr->src_addr = b_ip;
	iptr->dest_addr = c_ip;
    }
    else if(cptr->type == 0){
	// Reply from C
	tmp = ll_find(ping_list, cptr->id_seqnum);

	// Reply back to A
	if(tmp == NULL){
	    printf("ID not in LL. skipping\n");
	    return ;
	}
	memcpy(eptr->src_addr, b_macaddr, 6);
	memcpy(eptr->dest_addr, tmp->addr, 6);
	iptr->src_addr = b_ip;
	iptr->dest_addr = tmp->ip;
    }
    else{
	printf("Bad type %d. Ignoring\n", cptr->type);
	return ;
    }

    if(pcap_sendpacket(handle, tosend, pkthdr->caplen) != 0){
	pcap_perror(handle, "sendpacket fail");
	exit(1);
    }
}

void ll_insert(LL **tarp, struct in_addr ip, u_char addr[6], int id){
    LL *target;
    target = *tarp;

    if(target == NULL){
	target = (LL *)malloc(sizeof(LL));
	target->ip = ip;
	memcpy(target->addr, addr, 6);
	target->id = id;
	target->next = NULL;
	*tarp = target;
	return ;
    }
    else{
	ll_insert(&(target->next), ip, addr, id);
    }
}

LL* ll_find(LL *target, int id){
    if(target == NULL){
	return NULL;
    }
    else if(target->id == id){
	return target;
    }
    else{
	return ll_find(target->next, id);
    }
}
