#ifndef _MYPROXY_H_
#define _MYPROXY_H_
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>	// "struct sockaddr_in"
#include <arpa/inet.h>	// "in_addr_t"
#define MAX_STRING 1248
#define MAX_HEADER 10240
#define INITIAL_FILE_SIZE 10240
#define MAX_CHUNK_SIZE 500
int read_bytes(int accept_fd, int length, char* result_string)
{
	int countread,read_bytes = 0;
	while(read_bytes < length)
	{
		if((countread = recv(accept_fd, &result_string[read_bytes],length - read_bytes,0)) <0)
		{
			//perror("recv()");
            //printf("Sender closes connection.\n");
            return -1;
		}
		read_bytes += countread;
	}
    return 0;
}

int write_bytes(int accept_fd, char* input, int length)
{
	int writebytes=0, countwrite = 0;
	while(writebytes < length)
	{
        //the other side may turn off the socket
		if( (countwrite = send(accept_fd, &input[writebytes], length - writebytes,MSG_NOSIGNAL))<0)
		{
			//printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
            //printf("The client closes the connection.\n");
            return -1;
		}
		writebytes += countwrite;
	}
    return 0;
}

//user responsible for freeing
char* readheader(int accept_fd)
{
    char *mybuffer = malloc(MAX_HEADER);
    memset(mybuffer, 0, MAX_HEADER);
    //receive the message
    //counter is the next byte sequence to store
    int counter = 0;
    while(counter<5 || strcmp(&mybuffer[counter-4],"\r\n\r\n") !=0)
    {
        read_bytes(accept_fd, 1, &mybuffer[counter]);
        counter++;
    }
    return mybuffer;
}




#endif
