#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for(sum = 0; len > 1; len -= 2) sum += *buf++;
    if(len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum;
}

void send_packet(int sockfd, const char *src_ip, const char *dst_ip, int ttl) {
    char packet[sizeof(struct ip) + sizeof(struct icmphdr)];
    struct ip *ip_hdr = (struct ip *)packet;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ip));
    
    // IP Header
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(packet));
    ip_hdr->ip_id = htons(rand() % 65535);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = ttl;
    ip_hdr->ip_p = IPPROTO_ICMP;
    ip_hdr->ip_src.s_addr = inet_addr(src_ip);
    ip_hdr->ip_dst.s_addr = inet_addr(dst_ip);
    ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));
    
    // ICMP Header
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = htons(rand() % 65535);
    icmp_hdr->un.echo.sequence = htons(1);
    icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr));
    
    struct sockaddr_in dst_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr(dst_ip)
    };
    
    sendto(sockfd, packet, sizeof(packet), 0, 
          (struct sockaddr *)&dst_addr, sizeof(dst_addr));
}

int main() {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int));
    
    srand(time(0));
    char *local_ip = "127.0.0.1"; //dest ip
    
    printf("Sending 10 spoofed packets...\n");
    for(int i = 0; i < 10; i++) {
        char spoof_ip[16];
        sprintf(spoof_ip, "%d.%d.%d.%d", rand()%256, rand()%256, rand()%256, rand()%256);
        send_packet(sockfd, spoof_ip, local_ip, rand()%30 + 30); // Invalid TTLs
        usleep(100000);
    }
    
    printf("Sending 1 legitimate packet...\n");
    send_packet(sockfd, local_ip, local_ip, 64); // Correct TTL
    
    close(sockfd);
    return 0;
}   