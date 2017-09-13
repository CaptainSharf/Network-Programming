#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
#define ERRBUF_SIZE 100

struct stll{
    struct in_addr ip;
    u_char addr[6];
    int idntfr;
    struct stll *next;
};

struct __st_ethernet_header{
    u_char daddr[6];
    u_char saddr[6];
    u_short tp;
};

u_char c_macaddr[6], b_macaddr[6];
struct in_addr c_ip, b_ip;
pcap_t* handle;
struct stll *ping_list;


struct ip_header{
    u_char verno_hlngth;  // 4 bits version number, 4 bits (header lngthgth)/4
    u_char toss;
    u_short lngth;
    u_short idntfr;
    u_short offf_set;
    u_char ttyl;
    u_char protocol;
    u_short check_sum;
    struct in_addr saddr, daddr;
};

struct icmp_header{
    u_char tp;
    u_char cipher;
    u_short check_sum;
    int idntfr_seqnum;
};


void ll_insert(struct stll **tarp, struct in_addr ip, u_char addr[6], int idntfr){
    struct stll *trgt;
    trgt = *tarp;

    if(trgt == NULL){
    trgt = (struct stll *)malloc(sizeof(struct stll));
    trgt->ip = ip;
    memcpy(trgt->addr, addr, 6);
    trgt->idntfr = idntfr;
    trgt->next = NULL;
    *tarp = trgt;
    return ;
    }
    else{
    ll_insert(&(trgt->next), ip, addr, idntfr);
    }
}

struct stll* ll_find(struct stll *trgt, int idntfr){
    if(trgt == NULL){
    return NULL;
    }
    else if(trgt->idntfr == idntfr){
    return trgt;
    }
    else{
    return ll_find(trgt->next, idntfr);
    }
}
void b_callback(u_char *user_args, const struct pcap_pkthdr* pkthdr, const u_char *packet){
    struct __st_ethernet_header *eptr;
    struct ip_header *iptr;
    struct icmp_header *cptr;
    //    int i;
    u_char *tosend;
    struct stll *tmp;
    
    tosend = (u_char *)malloc(pkthdr->caplen);
    memcpy(tosend, packet, pkthdr->caplen);

    eptr = (struct __st_ethernet_header *)tosend;
    iptr = (struct ip_header *)(tosend + 14);
    cptr = (struct icmp_header *)(tosend + 14 + (iptr->verno_hlngth & 15)*4);

    printf("from %s ", inet_ntoa(iptr->saddr));
    printf("to %s\n", inet_ntoa(iptr->daddr));
    printf("tp: %d idntfr: %d\n", cptr->tp, cptr->idntfr_seqnum);

    if(cptr->tp == 8){
    // From A
    ll_insert(&ping_list, iptr->saddr, eptr->saddr, cptr->idntfr_seqnum);
    memcpy(b_macaddr, eptr->daddr, 6);

    // forward to C
    memcpy(eptr->saddr, b_macaddr, 6);
    memcpy(eptr->daddr, c_macaddr, 6);
    iptr->saddr = b_ip;
    iptr->daddr = c_ip;
    }
    else if(cptr->tp == 0){
    // Reply from C
    tmp = ll_find(ping_list, cptr->idntfr_seqnum);

    // Reply back to A
    if(tmp == NULL){
        printf("ID not in struct stll. skipping\n");
        return ;
    }
    size_t size_cpy = 6;
    memcpy(eptr->saddr, b_macaddr, size_cpy);
    memcpy(eptr->daddr, tmp->addr, size_cpy);
    iptr->saddr = b_ip;
    iptr->daddr = tmp->ip;
    }
    else{
    printf("Bad tp %d. Ignoring\n", cptr->tp);
    return ;
    }

    if(pcap_sendpacket(handle, tosend, pkthdr->caplen) != 0){
    pcap_perror(handle, "sendpacket fail");
    exit(1);
    }
}

int main(int argc, char *argv[]){ 
    char *dev, s[ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    unsigned int ar[6];
    int i;
    struct bpf_program fp;


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

    if(pcap_compile(handle, &fp, "icmp[icmptp] == icmp-echo || icmp[icmptp] == icmp-echoreply", 0, net) != 0){
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