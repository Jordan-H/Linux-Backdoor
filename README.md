<h1>Linux Backdoor</h1>

A program to demonstrate backdoor functionality

*NOTE* - TCP/ICMP is not completely implemented. UDP is the only working protocol in this implementation.

This implementation of a backdoor uses UDP to send a command that gets encrypted with a hard-coded password on both sides 
and is given a signature for commands being sent to/from the backdoor to ensure that only intended commands reach the backdoor.
The backdoor utilizes libpcap to sniff packets ensuring that any firewall rules will be irrelevant in the backdoor receiving packets 
as all packets will be sniffed directly off the NIC instead of listening for a packet on a specified port.


<h2>Call Back Client</h2>

The call back client(cbc) is compiled as follows:

`gcc -o cbc call-back-client.c`

It is then invoked as follows:

`./cbc <host> <port>`

The <host> is the IP address of the machine where the backdoor resides and the <port> is the port that 
the backdoor is listening on

<h2>Backdoor</h2>

The backdoor is created by using the makefile provided and is simply invoked as follows:

`./backdoor <packets> "udp and port <port>"`

The <packets> is how many packets that will be sniffed by the backdoor before exiting. It can be set to 0 or -1 to be ran indefinitely.
The <port> is the port that the backdoor will look for when it is sniffing packets to identify which packets are aimed for it.
