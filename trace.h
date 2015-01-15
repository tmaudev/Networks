/* Trace Program Header
 */

/* Libraries */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ether.h>

/* Checksum Header */
#include "checksum.h"

/* Constant Definitions */
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
#define HTTP 80
#define TELNET 23
#define FTP 20
#define POP3 110
#define SMTP 25
#define MAXSTR 10
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define FIN_FLAG 0x01
#define BUF_SIZE 1600

/* Ethernet Header Struct */
struct ethernet_header {
	char dest[MAC_LEN];
	char src[MAC_LEN];
	uint16_t type;
}__attribute__((packed));

/* ARP Header Struct */
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

/* IP Header Struct */
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

/* TCP Header Struct */
struct tcp_header {
	uint16_t src;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack;
	u_char offset;
	u_char flags;
	uint16_t winSize;
	uint16_t checksum;
	uint16_t	up;
}__attribute__((packed));

/* TCP Pseudo Header Struct */
struct pseudo_header {
	struct in_addr src;
	struct in_addr dest;
	u_char reserved;
	u_char protocol;
	uint16_t len;
}__attribute__((packed));

/* UDP Header Struct */
struct udp_header {
	uint16_t src;
	uint16_t dest;
	uint16_t len;
	uint16_t checksum;
}__attribute__((packed));

/* ICMP Header Struct */
struct icmp_header {
	u_char type;
	u_char opcode;
	u_char checksum;
}__attribute__((packed));

/* Function Prototypes */
void ethernet(const u_char *data);
void arp(const u_char *data);
void ip(const u_char *data);
void tcp(const u_char *data, int opt);
int pseudoBufferCheck(struct ip_header *ip, struct tcp_header *tcp, int opt);
char *tcpType(uint16_t port);
void udp(const u_char *data, int opt);
void icmp(const u_char *data, int opt);
char *protocolType(u_char protocol);
