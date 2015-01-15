/* Computer Networks: Program 2
 * Packet Trace
 *
 * Author: Tyler Mau
 * Date: January 12, 2015
 */

#include "trace.h"

int main(int argc, char **argv) {
   pcap_t *trace;
   struct pcap_pkthdr *header;
   const u_char *data;
   char errbuf[PCAP_ERRBUF_SIZE];
   int count = 1;

   if (argc != 2) {
      printf("Error: Must have one argument (PCAP File)\n");
   }
   trace = pcap_open_offline(argv[1], errbuf);
   while(pcap_next_ex(trace, &header, &data) == 1) {

      printf("\nPacket number: %d  Packet Len: %d\n", count++, header->len);
      ethernet(data);

   }
   pcap_close(trace);

   return 0;
}

void ethernet(const u_char *data) {
   struct ethernet_header *eheader;
   eheader = (struct ethernet_header *)data;

   printf("\n   Ethernet Header\n");
   printf("      Dest MAC: %s\n", ether_ntoa((struct ether_addr *)eheader->dest));
   printf("      Source MAC: %s\n", ether_ntoa((struct ether_addr *)eheader->src));
   printf("      Type: ");

   if (eheader->type == ARP) {
      printf("ARP\n");
      arp(data);
   }
   else if (eheader->type == IP) {
      printf("IP\n");
      ip(data);
   }
   else {
      printf("Unknown\n");
   }
}

void ip(const u_char *data) {
   struct ip_header *ip;
   ip = (struct ip_header *)(data + ETHERNET_SIZE);
   char check[10];
   int opt;

   printf("\n   IP Header\n");
   printf("      TOS: 0x%x\n", ip->tos);
   printf("      TTL: %d\n", ip->ttl);
   printf("      Protocol: %s\n", protocolType(ip->protocol));

   if (!in_cksum((unsigned short *)ip, sizeof(struct ip_header))) {
      strcpy(check, "Correct");
   }
   else {
      strcpy(check, "Incorrect");
   }

   printf("      Checksum: %s (0x%x)\n", check, ntohs(ip->checksum));

   printf("      Sender IP: %s\n", inet_ntoa(ip->src));
   printf("      Dest IP: %s\n", inet_ntoa(ip->dest));

   opt = ((ip->vers & MASK) << 2) - sizeof(struct ip_header);

   if (ip->protocol == TCP) {
      tcp(data, opt);
   }
   else if (ip->protocol == UDP) {
      udp(data, opt);
   }
   else if (ip->protocol == ICMP) {
      icmp(data, opt);
   }
}

char *protocolType(u_char protocol) {
   if (protocol == TCP) {
      return "TCP";
   }
   else if (protocol == UDP) {
      return "UDP";
   }
   else if (protocol == ICMP) {
      return "ICMP";
   }
   else {
      return "Unknown";
   }
}

void tcp(const u_char *data, int opt) {
   struct tcp_header *tcp;
   //struct ip_header *ip;
   //ip = (struct ip_header *)(data + ETHERNET_SIZE);
   tcp = (struct tcp_header *)(data + ETHERNET_SIZE + sizeof(struct ip_header) + opt);

   printf("   \nTCP Header\n");
   printf("      Source Port: ");

   if (!strcmp(tcpType(tcp->src), "")) {
      printf("%d\n", tcp->src);
   }
   else {
      printf("%s\n", tcpType(tcp->src));
   }

   printf("      Destination Port: ");

   if (!strcmp(tcpType(tcp->dest), "")) {
      printf("%d\n", tcp->dest);
   }
   else {
      printf("%s\n", tcpType(tcp->src));
   }

   printf("      Sequence Number: %u\n", ntohl(tcp->seq));
   printf("      ACK Number: %u\n", ntohl(tcp->ack));
}

char *tcpType(u_char port) {

   if (port == HTTP) {
      return "HTTP";
   }
   else if (port == TELNET) {
      return "TELNET";
   }
   else if (port == FTP) {
      return "FTP";
   }
   else if (port == POP3) {
      return "POP3";
   }
   else if (port == SMTP) {
      return "SMTP";
   }
   else {
      return "";
   }
}

void udp(const u_char *data, int opt) {
   struct udp_header *udp;
   udp = (struct udp_header *)(data + ETHERNET_SIZE + sizeof(struct ip_header) + opt);

   printf("   \nUDP Header\n");
   printf("      Source Port: %d\n", ntohs(udp->src));
   printf("      Dest Port: %d\n", ntohs(udp->dest));
}

void arp(const u_char *data) {
   struct arp_header *arp;
   arp = (struct arp_header *)(data + ETHERNET_SIZE);

   printf("\n   ARP header\n");
   printf("      Opcode: ");

   if (arp->opcode == REQUEST) {
      printf("Request\n");
   }
   else if (arp->opcode == REPLY) {
      printf("Reply\n");
   }
   else {
      printf("Unknown\n");
   }

   printf("      Sender MAC: %s\n", ether_ntoa((struct ether_addr *)arp->h_srcAddr));
   printf("      Sender IP: %s\n", inet_ntoa(arp->p_srcAddr));
   printf("      Target MAC: %s\n", ether_ntoa((struct ether_addr *)arp->h_destAddr));
   printf("      Target IP: %s\n", inet_ntoa(arp->p_destAddr));
}

void icmp(const u_char *data, int opt) {
   struct icmp_header *icmp;
   icmp = (struct icmp_header *)(data + ETHERNET_SIZE + sizeof(struct ip_header) + opt);

   printf("   \nICMP Header\n");
   printf("      Type: ");

   if (icmp->type == ICMP_REQUEST) {
      printf("Request\n");
   }
   else if (icmp->type == ICMP_REPLY) {
      printf("Reply\n");
   }
   else {
      printf("Unknown\n");
   }
}

