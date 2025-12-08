#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "misc.h"

#define LINE_SIZE 	255
#define SCREEN_SIZE 131072


int main(int argc, char *argv[])  {
 
    int sockfd, opt, portno; 
    int argCnt=0, nRead, nWrite;
    char ip[16];
    struct sockaddr_in servAddr;
    struct hostent *servName;

    char buffer[LINE_SIZE];
    char screen[SCREEN_SIZE];


    while ((opt = getopt(argc, argv, "a:p:")) != -1) {
           switch (opt) {
               case 'a':
                   strcpy(ip, optarg);
		   argCnt++;
                   break;
               case 'p':
                   portno = atoi(optarg);
		   argCnt++;
                   break;
               default: /* '?' */
                   fprintf(stderr, "Usage: %s [-a ip_address] [-p port_number] \n", argv[0]);
               exit(EXIT_FAILURE);
          }
    }

    if(argCnt != 2 )  {
       error("ERR>> missing arguments");
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd<0) {
      error("ERR>> socket creation failed");
    }

    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = inet_addr(ip);
    servAddr.sin_port = htons(portno);

    if (connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)  {
      error("ERR>> connection failed");
    }

	int exit_requested = 0;

	while(!exit_requested) {
		printf("waiting for a command : ");
		fgets(buffer, LINE_SIZE, stdin);
		
		if(!strncmp("exit\n", buffer, 5)) {
			nWrite = send(sockfd, "exit\n", 5, 0); 
			exit_requested = 1;
		} else {
			nWrite = send(sockfd, buffer, strlen(buffer), 0); 
			if (nWrite < 0)  {
			  error("ERR>> send failed...\n");
			}

			nRead = recv(sockfd, screen, SCREEN_SIZE, 0);
			if (nRead < 0) {
			  error("ERR> receive error...\n");
			}

			printf("\nReply from server : %s\n", screen);
		}
	}

	close(sockfd);
    return 0;
}
