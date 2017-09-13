#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>

#define PORT 9551



void *read_input(void *sock)
{
    int valread;
    char buffer[1024] = {0};
     while(1)
    {
        valread = read(*(int *)sock , buffer, 1024);
        printf("Client says:%s\n",buffer);
        int i=0;
        for(i=0;i<1024;i++)
            buffer[i]=0;
    }
}

void send_input(void* sock)
{
    char sending_buffer[1024] = {0};
    while(1)
    {
        //printf("Scanning server\n");
        scanf("%s",sending_buffer);
        send((int)sock , sending_buffer , strlen(sending_buffer) , 0 );
    }
}

int main(int argc, char const *argv[])
{
    int socket_fd, new_socket, valread;
    struct sockaddr_in server_adrs, clr;
    pthread_t thread;
    int status;
    int opt = 1;
    int addrlen = sizeof(server_adrs);
      
    // Creating socket file descriptor
    
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    printf("Created Socket...\n");

    //memset(&server_adrs, 0, sizeof(server_adrs));
    server_adrs.sin_family = AF_INET; 
    server_adrs.sin_addr.s_addr = INADDR_ANY;
    server_adrs.sin_port = htons( PORT );
    
    if (bind(socket_fd, (struct sockaddr *)&server_adrs, sizeof(server_adrs))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("binding...\n");
    if (listen(socket_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("listening...\n");
    if ((new_socket=accept(socket_fd, (struct sockaddr *)&clr, &addrlen))<0)
    {
        perror("Failed acc");
        exit(EXIT_FAILURE);
    }
    printf("Accepting...\n");
    int t1 = pthread_create(&thread,NULL,read_input,(void*)&new_socket);
    send_input((void*)new_socket);
    return 0;
}