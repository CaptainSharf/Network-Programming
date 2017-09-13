#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#define PORT_VAL 0

int Atoi(char *str)
{
    int res = 0; // Initialize result
  
    // Iterate through all characters of input string and
    // update result
    for (int i = 0; str[i] != '\0'; ++i)
        res = res*10 + str[i] - '0';
  
    // return result.
    return res;
}

int main(int argc, char *argv[]){
	int broadcast_sock, addl_arg;
	struct sockaddr_in in_sock;
	int PortValue = Atoi(argv[2]);
	broadcast_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

	// any IP can connect
	int x = PORT_VAL;
	in_sock.sin_port = htons(x);
	in_sock.sin_family = PF_INET;
	in_sock.sin_addr.s_addr = htonl(INADDR_ANY);

	int val = bind(broadcast_sock, (struct sockaddr *)&in_sock, sizeof(struct sockaddr_in));
	//printf("Binding successful\n");
	addl_arg = 1;
	if (setsockopt(broadcast_sock, SOL_SOCKET, SO_BROADCAST, &addl_arg, sizeof(int)) < 0){
		
		exit(1);
	}

	in_sock.sin_family = PF_INET;
	in_sock.sin_port = htons(PortValue); 

	val = inet_pton(PF_INET, argv[1], &in_sock.sin_addr);

	int val = sendto(broadcast_sock, argv[3], strlen(argv[3]), 0, (struct sockaddr *)&in_sock, sizeof(struct sockaddr_in));
	if(val<0){
		perror("Sending Failed");
		exit(1);
	}	
	return 0;
}