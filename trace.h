/* Trace Program Header
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "checksum.h"

#define ETHERNET_SIZE 14
#define MAC_LEN 6
#define ARP 1544
#define IP 8
#define TCP 6
#define UDP 17
#define ICMP 1
#define REQUEST 256
#define REPLY 512
#define ICMP_REQUEST 8
#define ICMP_REPLY 0
#define MASK 0x0F

struct ethernet_header {
	char dest[MAC_LEN];
	char src[MAC_LEN];
	uint16_t type;
}__attribute__((packed));

struct arp_header {
	uint16_t hardware;
	uint16_t protocol;
	u_char h_len;
	u_char p_len;
	uint16_t opcode;
	u_char h_srcAddr[MAC_LEN];
	struct in_addr p_srcAddr;
	u_char h_destAddr[MAC_LEN];
	struct in_addr p_destAddr;
}__attribute__((packed));

struct ip_header {
	u_char vers;
	u_char tos;
	uint16_t len;
	uint16_t id;
	uint16_t flags;
	u_char ttl;
	u_char protocol;
	uint16_t checksum;
	struct in_addr src;
	struct in_addr dest;
}__attribute__((packed));

struct udp_header {
	uint16_t src;
	uint16_t dest;
	uint16_t len;
	uint16_t checksum;
}__attribute__((packed));

struct icmp_header {
	u_char type;
	u_char opcode;
	u_char checksum;
}__attribute__((packed));

void ethernet(const u_char *data);
void arp(const u_char *data);
void ip(const u_char *data);
void udp(const u_char *data, int opt);
void icmp(const u_char *data, int opt);
char *protocolType(u_char protocol);
