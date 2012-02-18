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
#define BYTEPSEC_TO_MBITPSEC (8.0/1000000.0)

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
int leef_sniff_next_packet(struct leef_handle *handle, leef_sniffed_packet *packet, int timeout);

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
int64_t leef_proc_read_int(const char *path);
int64_t leef_if_tx_packets(const char *devname);
int64_t leef_if_tx_dropped(const char *devname);
int64_t leef_if_tx_bytes(const char *devname);
int64_t leef_if_rx_packets(const char *devname);
int64_t leef_if_rx_dropped(const char *devname);
int64_t leef_if_rx_bytes(const char *devname);
uint32_t leef_if_ipv4(const char *devname);

extern volatile unsigned long leef_txpackets;
extern volatile unsigned long leef_txbytes;
static inline unsigned long leef_get_txpackets() { return leef_txpackets; }
static inline unsigned long leef_get_txbytes() { return leef_txbytes; }

/* fast random implementation */
#define LEEF_MAX_RAND 65536

extern __thread unsigned long leef_next_rand_seed;

static inline void leef_srand(unsigned long next_rand_seed) {
    leef_next_rand_seed = next_rand_seed;
}

static inline int leef_rand() {
    leef_next_rand_seed = leef_next_rand_seed * 1103515245 + 12345;
    return ((unsigned)(leef_next_rand_seed/65536) % LEEF_MAX_RAND);
}

static inline int leef_random_range(int min, int max) {
    if(min > max) {
        int tmp = max;
        max = min;
        min = tmp;
    }
    double range = max - min + 1;
    int ret = (min + ((int)((range * leef_rand())/ (LEEF_MAX_RAND+1.0))));
    return ret;
}

static inline uint8_t leef_random_byte() { return (uint8_t)(leef_rand() % 256); }
static inline uint16_t leef_random_u16() { return (uint16_t)leef_rand(); }
static inline uint32_t leef_random_u32() { return (uint32_t)(leef_random_u16() << 16 | leef_random_u16()); }
static inline uint16_t leef_random_src_port() { return 32769 + (leef_rand() % 28232); }

#endif
