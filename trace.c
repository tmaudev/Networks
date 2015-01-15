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
      fprintf(stderr, "Error: Must have one argument (PCAP File)\n");
      return -1;
   }
   trace = pcap_open_offline(argv[1], errbuf);

   if (!trace) {
      fprintf(stderr, "%s\n", errbuf);
      return -1;
   }

   while(pcap_next_ex(trace, &header, &data) == 1) {

      printf("\nPacket number: %d  Packet Len: %d\n", count++, header->len);
      ethernet(data);

   }
   pcap_close(trace);

   return 0;
}

/* Parses Ethernet Header */
void ethernet(const u_char *data) {
   struct ethernet_header *eheader;
   eheader = (struct ethernet_header *)data;

   if (!eheader) {
      fprintf(stderr, "Error: No Ethernet Packet\n");
      return;
   }

   printf("\n   Ethernet Header\n");
   printf("      Dest MAC: %s\n", ether_ntoa((struct ether_addr *)eheader->dest));
   printf("      Source MAC: %s\n", ether_ntoa((struct ether_addr *)eheader->src));
   printf("      Type: ");

   if (eheader->type == ARP) {
      printf("ARP\n");
      /* Pass to ARP Function */
      arp(data);
   }
   else if (eheader->type == IP) {
      printf("IP\n");
      /* Pass to IP Function */
      ip(data);
   }
   else {
      printf("Unknown\n");
      printf("\nUnknown PDU\n");
   }
}

/* Parses IP Header */
void ip(const u_char *data) {
   struct ip_header *ip;
   ip = (struct ip_header *)(data + ETHERNET_SIZE);
   char check[MAXSTR];
   int opt;

   if (!ip) {
      fprintf(stderr, "Error: No IP Packet\n");
      return;
   }

   printf("\n   IP Header\n");
   printf("      TOS: 0x%x\n", ip->tos);
   printf("      TTL: %d\n", ip->ttl);
   printf("      Protocol: %s\n", protocolType(ip->protocol));

   /* Checksum */
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
      /* Pass to TCP Function */
      tcp(data, opt);
   }
   else if (ip->protocol == UDP) {
      /* Pass to UDP Function */
      udp(data, opt);
   }
   else if (ip->protocol == ICMP) {
      /* Pass to ICMP Function */
      icmp(data, opt);
   }
}

/* IP Support Function: Returns Protocol Type of IP Packet Data */
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

/* Parses TCP Header */
void tcp(const u_char *data, int opt) {
   struct tcp_header *tcp;
   struct ip_header *ip;
   ip = (struct ip_header *)(data + ETHERNET_SIZE);
   tcp = (struct tcp_header *)(data + ETHERNET_SIZE + sizeof(struct ip_header) + opt);
   char checkStr[MAXSTR];
   int check;

   if (!tcp) {
      fprintf(stderr, "Error: No TCP Packet\n");
      return;
   }

   printf("   \nTCP Header\n");
   printf("      Source Port: ");

   /* Checks TCP Source Port Type */
   if (!strcmp(tcpType(ntohs(tcp->src)), "")) {
      printf("%d\n", ntohs(tcp->src));
   }
   else {
      printf("%s\n", tcpType(ntohs(tcp->src)));
   }

   printf("      Dest Port: ");

   /* Checks TCP Destination Port Type */
   if (!strcmp(tcpType(ntohs(tcp->dest)), "")) {
      printf("%d\n", ntohs(tcp->dest));
   }
   else {
      printf("%s\n", tcpType(ntohs(tcp->dest)));
   }

   printf("      Sequence Number: %u\n", ntohl(tcp->seq));
   printf("      ACK Number: %u\n", ntohl(tcp->ack));

   printf("      SYN Flag: ");

   /* Check SYN Flag */
   if ((tcp->flags & SYN_FLAG) == SYN_FLAG) {
      printf("Yes\n");
   }
   else {
      printf("No\n");
   }

   /* Check Reset Flag */
   printf("      RST Flag: ");

   if ((tcp->flags & RST_FLAG) == RST_FLAG) {
      printf("Yes\n");
   }
   else {
      printf("No\n");
   }

   /* Check FIN Flag */
   printf("      FIN Flag: ");

   if ((tcp->flags & FIN_FLAG) == FIN_FLAG) {
      printf("Yes\n");
   }
   else {
      printf("No\n");
   }

   printf("      Window Size: %d\n", ntohs(tcp->winSize));

   check = pseudoBufferCheck(ip, tcp, opt);

   /* Checksum */
   if (!check) {
      strcpy(checkStr, "Correct");
   }
   else {
      strcpy(checkStr, "Incorrect");
   }

   printf("      Checksum: %s (0x%x)\n", checkStr, ntohs(tcp->checksum));
}

/* TCP Support Function: Create Pseudo TCP Header and Buffer*/
int pseudoBufferCheck(struct ip_header *ip, struct tcp_header *tcp, int opt) {
   struct pseudo_header pseudo;
   u_char *buf = malloc(BUF_SIZE);
   int check;

   pseudo.src = ip->src;
   pseudo.dest = ip->dest;
   pseudo.reserved = 0;
   pseudo.protocol = TCP;
   pseudo.len = htons(ntohs(ip->len) - (sizeof(struct ip_header) + opt));

   memcpy(buf, &pseudo, sizeof(struct pseudo_header));
   memcpy(buf + sizeof(struct pseudo_header), tcp, ntohs(pseudo.len));

   check = in_cksum((u_short *)buf, ntohs(pseudo.len) + sizeof(struct pseudo_header));

   free(buf);
   return check;
}

/* TCP Support Function: Return String of Port Type */
char *tcpType(uint16_t port) {

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

/* Parses UDP Header */
void udp(const u_char *data, int opt) {
   struct udp_header *udp;
   udp = (struct udp_header *)(data + ETHERNET_SIZE + sizeof(struct ip_header) + opt);

   if (!udp) {
      fprintf(stderr, "Error: No UDP Packet\n");
      return;
   }

   printf("   \nUDP Header\n");
   printf("      Source Port: %d\n", ntohs(udp->src));
   printf("      Dest Port: %d\n", ntohs(udp->dest));
}

/* Parses ARP Header */
void arp(const u_char *data) {
   struct arp_header *arp;
   arp = (struct arp_header *)(data + ETHERNET_SIZE);

   if (!arp) {
      fprintf(stderr, "Error: No ARP Packet\n");
      return;
   }

   printf("\n   ARP header\n");
   printf("      Opcode: ");

   /* Checks if Request or Reply */
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

/* Parses ICMP Header */
void icmp(const u_char *data, int opt) {
   struct icmp_header *icmp;
   icmp = (struct icmp_header *)(data + ETHERNET_SIZE + sizeof(struct ip_header) + opt);

   if (!icmp) {
      fprintf(stderr, "Error: No ICMP Packet\n");
      return;
   }

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

