/* Created by edubart FOR EDUCATIONAL AND TESTING purposes only.
 * Project page https://github.com/edubart/synack
 */

#ifndef LEEF_H
#define LEEF_H

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define LINK_ETHERNET       1
#define LINK_PPP            2
#define LINK_SLIP           3
#define LINK_PLIP           4
#define LINK_LOOPBACK       5
#define LINK_ISDN_RAWIP     6
#define LINK_ISDN_CISCOHDLC 7
#define LINK_CISCOHDLC      7
#define LINK_FDDI           8
#define LINK_FRAD           9
#define LINK_DLCI           10
#define LINK_TR             11
#define LINK_IPIP           12
#define LINK_VLAN           13
#define LINK_INVALID        0

#define SNIFF_BUFFER_SIZE 2048
#define SEND_BUFFER_SIZE 2048

enum e_tcp_flags {
    TCP_FIN = 0x01,
    TCP_SYN = 0x02,
    TCP_RST = 0x04,
    TCP_PUSH = 0x08,
    TCP_ACK = 0x10,
    TCP_URG = 0x20
};

struct leef_sniffed_packet
{
    union {
        struct tcphdr *tcp;
        struct udphdr *udp;
    } in_ip;
    struct iphdr *ip;
    uint16_t len;
    uint16_t linktype;
    uint8_t type;
    uint8_t buf[SNIFF_BUFFER_SIZE];
    uint8_t *packetbuf;
};

/* internal API */
int leef_adjust_sniffed_packet_buffer(struct leef_sniffed_packet *packet);
uint16_t leef_get_family_link_type(uint16_t family);

/* public API */
int leef_init();
void leef_terminate();

void leef_set_sniff_packet_size(int size);
int leef_sniff_next_packet(struct leef_sniffed_packet *packet);

int leef_send_raw_tcp(uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id, uint32_t seq, uint32_t ack_seq, uint8_t flags, uint16_t window, uint8_t ttl,
                      uint16_t data_size, uint8_t *data);
int leef_send_tcp_syn(uint32_t src_addr, uint32_t dest_addr, uint16_t src_port, uint16_t dest_port, uint32_t id, uint32_t seq);
int leef_send_tcp_ack(uint32_t src_addr, uint32_t dest_addr, uint16_t src_port, uint16_t dest_port, uint32_t id, uint32_t seq, uint32_t ack_seq);

uint32_t leef_resolve_hostname(const char *hostname);
uint16_t leef_checksum(uint16_t *ptr, int nbytes);

#endif
