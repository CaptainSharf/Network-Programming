#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>

#define PORT 9590

char hello[1024]={0};
char buffer[1024] = {0};

void *read_input(void *sock)
{
    int valread;
     while(1)
    {
        valread = read(*(int *)sock , buffer, 1024);
        printf("Server says:%s\n",buffer);
        int i=0;
        for(i=0;i<1024;i++)
            buffer[i]=0;
    }
}

void send_input(int sock)
{
    while(1)
    {
        //printf("Scanning client\n");
        scanf("%s",hello);
        send(sock , hello , strlen(hello) , 0 );
    }
}

int main(int argc, char const *argv[])
{
    int sock = 0, valread;
    struct sockaddr_in serv_addr,cl_addr;
    pthread_t thread;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    //File descriptor for server socket
    if (sock < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
    printf("Created Socket...\n");
    
    serv_addr.sin_family = AF_INET;  //Ipv4 
    serv_addr.sin_port = htons(PORT); //Port in binary form
    serv_addr.sin_addr.s_addr = INADDR_ANY; // inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }
    printf("Connected...\n");
    while(1)
    {
        //printf("Scanning client\n");
        scanf("%s",hello);
        send(sock , hello , strlen(hello) , 0 );
        valread = read(sock , buffer, 1024);
        printf("Server says:%s\n",buffer);
        int i=0;
        for(i=0;i<1024;i++)
            buffer[i]=0;
    }
    return 0;
}