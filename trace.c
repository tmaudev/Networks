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
   int type;

   if (argc != 2) {
      printf("Error: Must have one argument (PCAP File)\n");
   }
   trace = pcap_open_offline(argv[1], errbuf);
   pcap_next_ex(trace, &header, &data);

   type = ethernet(trace);

   pcap_close(trace);

   return 0;
}

static int ethernet(pcap_t *trace) {

}

static void ip() {

}

static void tcp() {

}

static void arp() {

}

static void icmp() {

}


