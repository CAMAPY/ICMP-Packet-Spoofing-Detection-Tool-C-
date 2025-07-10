#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <ifaddrs.h>

#define PACKET_SIZE 4096
#define MAX_IP_ENTRIES 1000
#define TTL_TOLERANCE 5
#define MAX_ID_DIFF 100

typedef struct {
    struct in_addr ip;
    uint8_t expected_ttl;
    uint16_t last_id;
    time_t last_seen;
} IpProfile;

IpProfile ip_db[MAX_IP_ENTRIES];
int db_count = 0;

const uint8_t common_ttls[] = {64, 128}; // Linux, Windows

// Get local IP address
char* get_local_ip() {
    static char ip[16] = {0};
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) return NULL;
    
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        if (strcmp(ifa->ifa_name, "lo") != 0) {
            strcpy(ip, inet_ntoa(addr->sin_addr));
            break;
        }
    }
    
    freeifaddrs(ifaddr);
    return ip;
}

uint8_t estimate_initial_ttl(uint8_t observed_ttl) {
    for(int i = 0; i < sizeof(common_ttls)/sizeof(common_ttls[0]); i++) {
        if(observed_ttl <= common_ttls[i] && 
           observed_ttl >= (common_ttls[i] - TTL_TOLERANCE)) {
            return common_ttls[i];
        }
    }
    return 0;
}

int check_ttl(struct ip *ip_hdr, char *local_ip) {
    // Special case for localhost
    if(strcmp(inet_ntoa(ip_hdr->ip_src), local_ip) == 0) {
        return (ip_hdr->ip_ttl == 64) ? 1 : 0;
    }

    for(int i = 0; i < db_count; i++) {
        if(ip_db[i].ip.s_addr == ip_hdr->ip_src.s_addr) {
            int diff = abs(ip_hdr->ip_ttl - ip_db[i].expected_ttl);
            return (diff <= TTL_TOLERANCE) ? 1 : 0;
        }
    }

    uint8_t initial_ttl = estimate_initial_ttl(ip_hdr->ip_ttl);
    if(initial_ttl == 0) return 0;

    if(db_count < MAX_IP_ENTRIES) {
        ip_db[db_count].ip = ip_hdr->ip_src;
        ip_db[db_count].expected_ttl = initial_ttl;
        ip_db[db_count].last_id = 0; // Initialize to track first packet
        ip_db[db_count].last_seen = time(NULL);
        db_count++;
    }
    
    return 1;
}

int check_ip_id(struct ip *ip_hdr) {
    uint16_t current_id = ntohs(ip_hdr->ip_id);
    
    for(int i = 0; i < db_count; i++) {
        if(ip_db[i].ip.s_addr == ip_hdr->ip_src.s_addr) {
            if(ip_db[i].last_id == 0) {
                ip_db[i].last_id = current_id;
                return 0;
            }
            
            int id_diff = current_id - ip_db[i].last_id;
            ip_db[i].last_id = current_id;
            return (id_diff > 0 && id_diff < MAX_ID_DIFF) ? 0 : 1;
        }
    }
    return 0; 
}

void process_packet(char *buffer, ssize_t size, char *local_ip) {
    struct ip *ip_hdr = (struct ip *)buffer;
    unsigned int ip_header_len = ip_hdr->ip_hl * 4;
    
    if(size < (ssize_t)(ip_header_len + sizeof(struct icmphdr)))
        return;

    struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + ip_header_len);
    if(icmp_hdr->type != ICMP_ECHO) return;

    char *src_ip = inet_ntoa(ip_hdr->ip_src);
    int ttl_valid = check_ttl(ip_hdr, local_ip);
    int id_valid = check_ip_id(ip_hdr);

    printf("Packet from: %-15s", src_ip);
    printf(" TTL: %-3d [%s]", ip_hdr->ip_ttl, ttl_valid ? "OK " : "BAD");
    printf(" IP ID: %-5d [%s]", ntohs(ip_hdr->ip_id), id_valid ? "OK " : "BAD");
    
    if(!ttl_valid || !id_valid) {
        printf("\n  \033[1;31mSPOOF DETECTED\033[0m - Basis: ");
        if(!ttl_valid) printf("TTL anomaly ");
        if(!id_valid) printf("ID anomaly");
    }
    printf("\n");
}

int main() {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd < 0) {
        perror("socket");
        return 1;
    }

    char *local_ip = get_local_ip();
    printf("Spoof Detector Running on %s\n", local_ip);
    printf("Listening for ICMP packets...\n\n");

    struct in_addr local_addr;
    inet_aton(local_ip, &local_addr);
    ip_db[db_count].ip = local_addr;
    ip_db[db_count].expected_ttl = 64;
    ip_db[db_count].last_id = 0;
    db_count++;

    char buffer[PACKET_SIZE];
    while(1) {
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        
        ssize_t size = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                               (struct sockaddr *)&src_addr, &addr_len);
        if(size < 0) continue;
        
        process_packet(buffer, size, local_ip);
    }

    close(sockfd);
    return 0;
}