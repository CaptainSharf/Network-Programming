#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include<arpa/inet.h>

#define ETHER_ADDR_LEN 6

typedef struct __st_ll{
    char s[16];
    int count;
    struct __st_ll *next;
}LL;

typedef struct __st_ethernet_header{
    u_char dest_addr[ETHER_ADDR_LEN];
    u_char src_addr[ETHER_ADDR_LEN];
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

void c_callback(u_char *,const struct pcap_pkthdr *,const u_char*);
void ll_insert(LL **, char *);
void ll_print(LL *);

LL *addr_list;

int main(int argc, char *argv[]){ 
    char *dev; 
    char s[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    bpf_u_int32 net, mask;
    struct bpf_program fp;

    if(argc != 1){
	fprintf(stdout,"Usage: %s\n",argv[0]);
	return 0;
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
    if(pcap_setdirection(handle,PCAP_D_IN) != 0){
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

    addr_list = NULL;
    printf("Start listening\n");
    pcap_loop(handle, 0, c_callback, NULL);

    printf("\nMust NOT print\n");
    return 0;
}

void c_callback(u_char *user_args, const struct pcap_pkthdr* pkthdr, const u_char *packet){
    IP_HEAD *iptr;

    iptr = (IP_HEAD *)(packet + 14);

    ll_insert(&addr_list, inet_ntoa(iptr->src_addr));
    ll_print(addr_list);
}

void ll_insert(LL **tarp, char *s){
    LL *target;
    target = *tarp;

    if(target == NULL){
	target = (LL *)malloc(sizeof(LL));
	strcpy(target->s, s);
	target->count = 1;
	target->next = NULL;
	*tarp = target;
	return ;
    }

    if(strcmp(target->s, s) == 0){
	target->count++;
    }
    else{
	ll_insert(&(target->next), s);
    }
}

void ll_print(LL *target){
    if(target == NULL){
	printf("\n");
	return ;
    }
    printf("%s:\t%d\n", target->s, target->count);
    ll_print(target->next);
}
