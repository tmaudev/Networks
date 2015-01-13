/* Trace Program Header
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#define MAC_LEN 6
#define ARP 1544
#define IP 8

struct ethernet_header {
	char dest[MAC_LEN];
	char src[MAC_LEN];
	uint16_t type;
};

void ethernet(const u_char *data);
void ip(const u_char *data);
