/* libleef - A small library for packet sniff and injection,
 * created by edubart - https://github.com/edubart
 */

#ifndef LEEF_H
#define LEEF_H

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

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
    TCP_FIN     = 0x01,
    TCP_SYN     = 0x02,
    TCP_RST     = 0x04,
    TCP_PUSH    = 0x08,
    TCP_ACK     = 0x10,
    TCP_URG     = 0x20
};

typedef struct {
    union {
        struct tcphdr *tcp;
        struct udphdr *udp;
        struct icmphdr *icmp;
    } in_ip;
    struct iphdr *ip;
    uint16_t len;
    uint16_t linktype;
    uint8_t type;
    uint8_t buf[SNIFF_BUFFER_SIZE];
    uint8_t *packetbuf;
} leef_sniffed_packet;

struct leef_handle
{
    int send_socket;
    int sniff_socket;
    int sniff_size;
    uint8_t send_buf[SEND_BUFFER_SIZE];
};

enum e_leef_init_flags {
    SNIFFING                = 0x01,
    INJECTING               = 0x02,
    SNIFFING_AND_INJECTING  = 0x03
};

int leef_init(struct leef_handle *handle, int init_flags);
void leef_terminate(struct leef_handle *handle);

void leef_set_sniff_packet_size(struct leef_handle *handle, int size);
int leef_sniff_next_packet(struct leef_handle *handle, leef_sniffed_packet *packet);

int leef_send_raw_tcp(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id, uint32_t seq, uint32_t ack_seq,
                      uint16_t frag_off, uint8_t flags,
                      uint16_t window, uint8_t ttl,
                      uint8_t tcp_options_size, uint8_t *tcp_options,
                      uint16_t data_size, uint8_t *data);
int leef_send_raw_tcp2(struct leef_handle *handle,
                       uint32_t src_addr, uint32_t dest_addr,
                       uint16_t src_port, uint16_t dest_port,
                       uint32_t id, uint32_t seq, uint32_t ack_seq,
                       uint8_t flags,
                       uint16_t data_size, uint8_t *data);
int leef_send_tcp_syn(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id, uint32_t seq,
                      int use_tcp_options);
int leef_send_tcp_ack(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id, uint32_t seq, uint32_t ack_seq);

int leef_send_raw_udp(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id,
                      uint16_t frag_off, uint8_t ttl,
                      uint16_t data_size, uint8_t *data);
int leef_send_udp_data(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id,
                      uint16_t data_size, uint8_t *data);

const char *leef_name_tcp_flags(leef_sniffed_packet *packet);
uint32_t leef_resolve_hostname(const char *hostname);
uint32_t leef_string_to_addr(const char *str);
char *leef_addr_to_string(uint32_t addr);

uint32_t leef_get_ticks();
void leef_srand();
int leef_random_range(int min, int max);
uint8_t leef_random_byte();
uint16_t leef_random_u16();
uint32_t leef_random_u32();
uint16_t leef_random_src_port();

int64_t leef_proc_read_int(const char *path);
int64_t leef_if_tx_packets(const char *devname);
int64_t leef_if_tx_bytes(const char *devname);
uint32_t leef_if_ipv4(const char *devname);

#endif
