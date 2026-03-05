#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void printPayload(unsigned char *data, int len) {
    printf("  Payload : ");
    for (int i = 0; i < len && i < 80; i++)
        printf("%c", (data[i] >= 32 && data[i] < 127) ? data[i] : '.');
    printf("%s\n", len > 80 ? "..." : "");
}

int parseTCP(unsigned char *buffer, struct iphdr *ip) {
    struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));

    printf("------ TCP -------------------------------------\n");
    printf("  Src Port : %d\n", ntohs(tcp->source));
    printf("  Dst Port : %d\n", ntohs(tcp->dest));
    printf("  Flags    : ");
    if (tcp->syn == 1) {printf("SYN ");};
    if (tcp->ack == 1) {printf("ACK ");};
    if (tcp->fin == 1) {printf("FIN ");};
    if (tcp->rst == 1) {printf("RST ");};
    if (tcp->psh == 1) {printf("PSH ");};
    printf("\n");

    unsigned char *payload = (unsigned char *)tcp + (tcp->doff * 4);
    int len = ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);
    if (len > 0) {printPayload(payload, len);};

    return 1;
}

int parseUDP(unsigned char *buffer, struct iphdr *ip) {
    struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));

    printf("------ UDP -------------------------------------\n");
    printf("  Src Port : %d\n", ntohs(udp->source));
    printf("  Dst Port : %d\n", ntohs(udp->dest));
    printf("  Length   : %d\n", ntohs(udp->len));

    return 1;
}

int processPacket(int size, unsigned char *buffer) {
    if (size < 0) {
        perror("packet");

        return 0;
    }

    // This is just to filter loopback packets which are very uninteresting and fill up the terminal
    struct ethhdr *eth = (struct ethhdr *) buffer;
    if (eth->h_source[0] == 0 && eth->h_source[1] == 0 &&
        eth->h_source[2] == 0 && eth->h_source[3] == 0 &&
        eth->h_source[4] == 0 && eth->h_source[5] == 0) return 0;

    printf("Packet captured: %d bytes \n", size);

    for (int i = 0; i<=15; i++) {
        printf("%02x ", buffer[i]);
    }

    printf("\n------ Ethernet Frame --------------------------\n");
    printf("  Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("  Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        printf("  Protocol: IPv4  (0x%04x)\n", ntohs(eth->h_proto));
    } else if (ntohs(eth->h_proto) == ETH_P_IPV6) {
        printf("  Protocol: IPv6  (0x%04x)\n\n\n", ntohs(eth->h_proto));
        return 1;
    } else if (ntohs(eth->h_proto) == ETH_P_ARP) {
        printf("  Protocol: ARP   (0x%04x)\n\n\n", ntohs(eth->h_proto));
        return 1;
    } else {
        printf("  Protocol: Other (0x%04x)\n\n\n", ntohs(eth->h_proto));
        return 1;
    }

    
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;
    printf("------ IP Header -------------------------------\n");
    printf("  Src IP  : %s\n", inet_ntoa(src));
    printf("  Dst IP  : %s\n", inet_ntoa(dst));
    printf("  TTL     : %d\n", ip->ttl);
    if (ip->protocol == 6) {
        printf("  Protocol: TCP\n");
        parseTCP(buffer, ip);
    } else if (ip->protocol == 17) {
        printf("  Protocol: UDP\n");
        parseUDP(buffer, ip);
    } else if (ip->protocol == 1) {
        printf("  Protocol: ICMP\n");
    } else {
        printf("  Protocol: Other\n");
    }
    

    puts("\n");
    return 1;
}

int main() {
    int running = 1;
    unsigned char buffer[65536];
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock < 0) {
        perror("socket");

        return 0;
    }

    puts("Running!");
    while (running) {
        int packet = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);

        processPacket(packet, buffer);
    }

    return 1;
}