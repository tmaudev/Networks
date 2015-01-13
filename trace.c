/* Computer Networks: Program 1
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
   int type, count = 1;

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

   printf("\nEthernet Header Output:\n\n");
   printf("Dest MAC: %s\n", ether_ntoa((struct ether_addr *)eheader->dest));
   printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eheader->src));
   printf("Type: ");

   if (eheader->type == ARP) {
      printf("ARP\n");
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

}

void tcp() {

}

void arp() {

}

void icmp() {

}


