#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>

#include "misc.h"

#define LINE_SIZE 	255
#define SCREEN_SIZE	1024
#define PRM_LEN		32
#define PRM_NUM		100
#define BACK_LOG	5

#define MAX_OUTPUT_BUFFER_LENGTH 131072

int main(int argc, char *argv[])  {

    int i, n, child_pid;
    int opt, argCnt=0, processCnt;
    int sockfd, newsockfd, portno, clilen; 	// int variable that is used later
    struct sockaddr_in serv_addr, cli_addr; 	//calling the library struct
    char buffer[LINE_SIZE]; 			//buffer of size created
    char **args;
    char prog[32];


    while ((opt = getopt(argc, argv, "n:p:")) != -1) {
           switch (opt) {
               case 'n':
                   processCnt = atoi(optarg);
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

    //1st IP Address 2nd TCP Concept 3rd Socket
    sockfd= socket(AF_INET, SOCK_STREAM,0);
    if(sockfd == -1)  {
      error("ERR>> socket creation failed");
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    // convert and use port number 
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)  {
      error("ERR>> can not bind to socket");
    }

    listen(sockfd, BACK_LOG);
    clilen = sizeof(cli_addr);


	int cur_childcount = 0;
	int responder_childpid = -1;

	pid_t children[processCnt];
	bzero(children, sizeof(pid_t) * processCnt);

    //
    //The new socket for the client informations
    //
	
	while(1) {
		int idx, wstatus;

		// a better solution might spawning another thread to check whether any child has died,
		// couldnt make it in time
		// right now the 4. client has to retry after a failed attempt
		// so that the last child that died can be processed.
		for(idx = 0; idx < processCnt; idx++) {
			if (children[idx] > 0) {
				if (waitpid(children[idx], &wstatus, WNOHANG) > 0) {
					printf("children with pid %d terminated.\n", children[idx]);
					children[idx] = 0;
					cur_childcount -= 1;
				}
			}
		}

		newsockfd = accept(sockfd,(struct sockaddr *) &cli_addr, (socklen_t *)&clilen);

		if (newsockfd < 0)  {
			  error("ERR>> can not accept");
			  close(sockfd);
			  exit(-1);
		}

		if ( cur_childcount < processCnt ) {
			if( (responder_childpid = fork()) == -1) {
				fprintf(stderr, "failed creating child.\n");
			} else {
				if (responder_childpid == 0) {
					int exit_requested = 0;

					while(!exit_requested) {

						bzero(buffer, LINE_SIZE); //Clears the buffer
						n = recv(newsockfd, buffer, LINE_SIZE, 0);
						if (n < 0)  {
							error("ERR>> can not read from socket");
						}

						//Buffer Stores the msg sent by the client
						printf("Here is the entered bash command: %s\n",buffer);

						args = malloc(PRM_NUM * sizeof(char *));

						for(i = 0;i < PRM_NUM; i++)
							args[i]=malloc(PRM_LEN *sizeof(char));

						//Running the Bash Commands
						if(readAndParseCmdLine(buffer, prog, args)) {
							if (!strncmp("exit", buffer, 4)) {
								exit_requested = 1;
							} else {
								int fds[2] = { 0 };

								if (pipe(fds)) { fprintf(stderr, "ERROR: pipe failed\n"); exit(1); }

								child_pid =fork();

								if(child_pid == 0){ //child part
									close(fds[0]);
									dup2(fds[1], 1);
									execvp(prog, args);  // create and run the new process and close the child process
									printf("Error in excuting the command- please make sure you type the right syntax.\n");
								} else{ //parent part
									close(fds[1]);
									wait(&child_pid);

									char output_buffer[MAX_OUTPUT_BUFFER_LENGTH] = { 0 };
									int rc = read(fds[0], output_buffer, MAX_OUTPUT_BUFFER_LENGTH - 1);

									output_buffer[rc + 1] = '\0';

									printf("output_length: %d\n", rc);

									if (rc == -1) {
										fprintf(stderr, "ERROR: couldn't read from child pipe");
									} else {
										n = send(newsockfd, output_buffer, rc + 1, 0);
										if (n < 0)  {
											error("ERROR writing to socket");
										}
									}

									close(fds[0]);
								}
							}
						}

						for(i = 0;i < PRM_NUM; i++) {
							free(args[i]);
						}
					int idx, wstatus;

						free(args);
					}

					close(newsockfd);
					//close(sockfd);
					exit(0);
				} else {

					int idx, written = 0;

					for(idx = 0; idx < processCnt; idx++) {
						if (children[idx] == 0 && !written) {
							children[idx] = responder_childpid;
							written = 1;
						}
					}

					printf("Connection from: %s:%d\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

					cur_childcount += 1;

					printf("cur child count: %d\n", cur_childcount);
				}

				close(newsockfd);
			}

		} else {
			fprintf(stderr, "max child count reached. what do we do?, the failing client should retry connecting\n");

			int idx, wstatus;

			for(idx = 0; idx < processCnt; idx++) {
				if (children[idx] > 0) {
					if (waitpid(children[idx], &wstatus, WNOHANG) > 0) {
						printf("children with pid %d terminated.\n", children[idx]);
						children[idx] = 0;
						cur_childcount -= 1;
					}
				}
			}
		}
	}
}


