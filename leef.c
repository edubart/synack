/* libleef - A small library for packet sniff and injection,
 * created by edubart - https://github.com/edubart
 */

#include "leef.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_fddi.h>
#include <pthread.h>

struct pseudo_header {
    uint32_t saddr, daddr;
    uint8_t res;
    uint8_t proto;
    uint16_t len;
};

__thread unsigned long leef_next_rand_seed;
volatile unsigned long leef_txpackets = 0;
volatile unsigned long leef_txbytes = 0;

int leef_adjust_sniffed_packet_buffer(leef_sniffed_packet *packet)
{
    switch(packet->linktype) {
        case LINK_ETHERNET:
        case LINK_LOOPBACK:
        case LINK_PLIP:
            packet->packetbuf = packet->buf + ETH_HLEN;
            return 1;
        case LINK_PPP:
        case LINK_SLIP:
        case LINK_ISDN_RAWIP:
        case LINK_IPIP:
            packet->packetbuf = packet->buf;
            return 1;
        case LINK_ISDN_CISCOHDLC:
        case LINK_FRAD:
        case LINK_DLCI:
            packet->packetbuf = packet->buf + 4;
            return 1;
        case LINK_FDDI:
            packet->packetbuf = packet->buf + sizeof(struct fddihdr);
            return 1;
        case LINK_VLAN:
            packet->packetbuf = packet->buf + 18;
            return 1;
        default:
            packet->packetbuf = NULL;
            return 0;
    }
}

uint16_t leef_get_family_link_type(uint16_t family)
{
    uint16_t result = 0;
    switch (family) {
        case ARPHRD_ETHER:
            result = LINK_ETHERNET;
            break;
        case ARPHRD_LOOPBACK:
            result = LINK_LOOPBACK;
            break;
        case ARPHRD_SLIP:
        case ARPHRD_CSLIP:
        case ARPHRD_SLIP6:
        case ARPHRD_CSLIP6:
            result = LINK_SLIP;
            break;
        case ARPHRD_PPP:
            result = LINK_PPP;
            break;
        case ARPHRD_FDDI:
            result = LINK_FDDI;
            break;
        case ARPHRD_IEEE802:
        case ARPHRD_IEEE802_TR:
            result = LINK_TR;
            break;
        case ARPHRD_FRAD:
            result = LINK_FRAD;
            break;
        case ARPHRD_DLCI:
            result = LINK_DLCI;
            break;
        case ARPHRD_HDLC:
            result = LINK_CISCOHDLC;
            break;
        case ARPHRD_TUNNEL:
            result = LINK_IPIP;
            break;
        default:
            result = LINK_INVALID;
            break;
    }
    return result;
}

uint16_t leef_checksum(register uint16_t *ptr, register int nbytes)
{
    register uint32_t sum = 0;
    uint16_t oddbyte;

    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1) {
        oddbyte = 0;
        *((uint8_t *) &oddbyte) = *(uint8_t *)ptr;
        sum += oddbyte;
    }

    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

int leef_init(struct leef_handle *handle, int flags)
{
    leef_get_ticks();

    /* seed random */
    struct timeval tv;
    gettimeofday(&tv, 0);
    leef_srand(tv.tv_usec * (unsigned long)pthread_self());

    handle->send_socket = -1;
    handle->sniff_socket = -1;
    handle->sniff_size = SNIFF_BUFFER_SIZE;

    if(flags & SNIFFING) {
        handle->sniff_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if(handle->sniff_socket == -1) {
            fprintf(stderr, "Unable to create the raw socket! (Are you root?)\n");
            return 0;
        }
    }

    if(flags & INJECTING) {
        handle->send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if(handle->send_socket == -1) {
            fprintf(stderr, "Unable to create the raw socket! (Are you root?)\n");
            return 0;
        }

        int hdrincl_on = 1;
        if(setsockopt(handle->send_socket, IPPROTO_IP, IP_HDRINCL, (char *)&hdrincl_on, sizeof(hdrincl_on)) == -1) {
            fprintf(stderr, "Unable to set IP_HDRINCL option!\n");
            return 0;
        }
    }
    return 1;
}

void leef_terminate(struct leef_handle *handle)
{
    if(handle->send_socket != -1) {
        close(handle->send_socket);
    }
    if(handle->sniff_socket != -1) {
        close(handle->sniff_socket);
    }
}

void leef_set_sniff_packet_size(struct leef_handle *handle, int size)
{
    handle->sniff_size = size;
}

int leef_sniff_next_packet(struct leef_handle *handle, leef_sniffed_packet *packet, int timeout)
{
    socklen_t fromlen = sizeof(struct sockaddr_ll);
    struct sockaddr_ll fromaddr;
    struct ifreq ifr;
    fd_set set;
    struct timeval tv;
    int ss;

    FD_ZERO(&set);
    FD_SET(handle->sniff_socket, &set);

    tv.tv_sec = 0;
    tv.tv_usec = timeout * 1000;

    /*
    do {
        ss = select(handle->sniff_socket + 1, &set, 0, 0, &tv);
    } while ((ss < 0) && (errno == EINTR));
    */

    ss = select(handle->sniff_socket + 1, &set, 0, 0, &tv);

    if(ss != -1 && FD_ISSET(handle->sniff_socket, &set)) {
        if(recvfrom(handle->sniff_socket, packet->buf, handle->sniff_size, 0, (struct sockaddr *)&fromaddr, &fromlen) == 0) {
            return 0;
        }

        ifr.ifr_ifindex = fromaddr.sll_ifindex;
        ioctl(handle->sniff_socket, SIOCGIFNAME, &ifr);

        if(ntohs(fromaddr.sll_protocol) != ETH_P_IP) {
            return 0;
        }

        packet->type = fromaddr.sll_pkttype;
        packet->linktype = leef_get_family_link_type(fromaddr.sll_hatype);

        if(!leef_adjust_sniffed_packet_buffer(packet)) {
            static int warned = 0;
            if(!warned ) {
              printf("WARNING: could not adjust packet offset for interface %s with link type %d, report the developer\n", ifr.ifr_name, packet->linktype);
              fflush(stdout);
              warned = 1;
            }
            return 0;
        }

        packet->ip = (struct iphdr *) (packet->packetbuf);
        packet->len = htons(packet->ip->tot_len) + (uint16_t)abs((int)(packet->packetbuf - packet->buf));
        if(packet->ip->protocol == IPPROTO_TCP) {
            packet->in_ip.tcp = (struct tcphdr *) ((char *) packet->ip + packet->ip->ihl * 4);
            packet->in_ip.tcp->source = htons(packet->in_ip.tcp->source);
            packet->in_ip.tcp->dest = htons(packet->in_ip.tcp->dest);
            packet->in_ip.tcp->seq = htonl(packet->in_ip.tcp->seq);
            packet->in_ip.tcp->ack_seq = htonl(packet->in_ip.tcp->ack_seq);
            packet->in_ip.tcp->window = htons(packet->in_ip.tcp->window);
        } else if(packet->ip->protocol == IPPROTO_UDP) {
            packet->in_ip.udp = (struct udphdr *) ((char *) packet->ip + packet->ip->ihl * 4);
            packet->in_ip.udp->source = htons(packet->in_ip.udp->source);
            packet->in_ip.udp->dest = htons(packet->in_ip.udp->dest);
            packet->in_ip.udp->len = htons(packet->in_ip.udp->len);
        } else if(packet->ip->protocol == IPPROTO_ICMP) {
            packet->in_ip.icmp = (struct icmphdr *) ((char *) packet->ip + packet->ip->ihl * 4);
        }

        /* convert */
        packet->ip->tot_len = htons(packet->ip->tot_len);
        packet->ip->id = htons(packet->ip->id);

        return 1;
    }
    return 0;
}

int leef_send_raw_tcp(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id, uint32_t seq, uint32_t ack_seq,
                      uint16_t frag_off, uint8_t flags,
                      uint16_t window, uint8_t ttl,
                      uint8_t tcp_options_size, uint8_t *tcp_options,
                      uint16_t data_size, uint8_t *data)
{
    struct sockaddr_in sktsin;
    struct pseudo_header *pseudoh = (struct pseudo_header *)(handle->send_buf + sizeof(struct iphdr) - sizeof(struct pseudo_header));
    struct iphdr *iph = (struct iphdr *)handle->send_buf;
    struct tcphdr *tcph = (struct tcphdr *)(handle->send_buf + sizeof(struct iphdr));
    uint8_t *packet_buff = handle->send_buf;
    uint16_t packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_options_size + data_size;
    uint16_t protocol_len = sizeof(struct tcphdr) + tcp_options_size + data_size;


    /* build tcp header */
    tcph->source = htons(src_port);
    tcph->dest = htons(dest_port);
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack_seq);
    tcph->doff = (sizeof(struct tcphdr) + tcp_options_size) / 4;
    tcph->window = htons(window);
    tcph->fin = (flags & TCP_FIN) ? 1 : 0;
    tcph->syn = (flags & TCP_SYN) ? 1 : 0;
    tcph->rst = (flags & TCP_RST) ? 1 : 0;
    tcph->psh = (flags & TCP_PUSH) ? 1 : 0;
    tcph->ack = (flags & TCP_ACK) ? 1 : 0;
    tcph->urg = (flags & TCP_URG) ? 1 : 0;
    tcph->res1 = 0;
    tcph->res2 = 0;
    tcph->urg_ptr = 0;
    tcph->check = 0;

    if(tcp_options_size > 0)
        memcpy((uint8_t *)tcph + sizeof(struct tcphdr), tcp_options, tcp_options_size);

    if(data_size > 0)
        memcpy(packet_buff + sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_options_size, data, data_size);

    /* calculate tcp checksum */
    pseudoh->saddr = src_addr;
    pseudoh->daddr = dest_addr;
    pseudoh->res = 0;
    pseudoh->proto = IPPROTO_TCP;
    pseudoh->len = htons(protocol_len);
    tcph->check = leef_checksum((uint16_t *)pseudoh, sizeof(struct pseudo_header) + protocol_len);

    /* build ip header */
    iph->version = 4;
    iph->ihl = 5;
    iph->tot_len = htons(packet_size);
    iph->id = htons(id);
    iph->frag_off = frag_off;
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = src_addr;
    iph->daddr = dest_addr;
    iph->tos = 0;
    iph->check = 0;

    /* calculate ip checksum */
    iph->check = leef_checksum((uint16_t *)iph, packet_size);

    /* send the packet */
    sktsin.sin_addr.s_addr = dest_addr;
    sktsin.sin_family = AF_INET;
    sktsin.sin_port = 0;
    int sent = sendto(handle->send_socket,
                      packet_buff, packet_size,
                      0,
                      (struct sockaddr *)&sktsin,
                      sizeof(struct sockaddr));
    if(sent > 0) {
      __sync_fetch_and_add(&leef_txpackets, 1);
      __sync_fetch_and_add(&leef_txbytes, packet_size + ETH_HLEN);
    }
    return sent;
}

int leef_send_raw_udp(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id,
                      uint16_t frag_off, uint8_t ttl,
                      uint16_t data_size, uint8_t *data)
{
    struct sockaddr_in sktsin;
    struct pseudo_header *pseudoh = (struct pseudo_header *)(handle->send_buf + sizeof(struct iphdr) - sizeof(struct pseudo_header));
    struct iphdr *iph = (struct iphdr *)handle->send_buf;
    struct udphdr *udph = (struct udphdr *)(handle->send_buf + sizeof(struct iphdr));
    uint8_t *packet_buff = handle->send_buf;
    uint16_t packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + data_size;
    uint16_t protocol_len = sizeof(struct udphdr) + data_size;

    /* build udp header */
    udph->source = htons(src_port);
    udph->dest = htons(dest_port);
    udph->len = htons(protocol_len);
    udph->check = 0;

    if(data_size > 0)
        memcpy(packet_buff + sizeof(struct iphdr) + sizeof(struct udphdr), data, data_size);

    /* calculate udp checksum */
    pseudoh->saddr = src_addr;
    pseudoh->daddr = dest_addr;
    pseudoh->res = 0;
    pseudoh->proto = IPPROTO_UDP;
    pseudoh->len = htons(protocol_len);
    udph->check = leef_checksum((uint16_t *)pseudoh, sizeof(struct pseudo_header) + protocol_len);

    /* build ip header */
    iph->version = 4;
    iph->ihl = 5;
    iph->tot_len = htons(packet_size);
    iph->id = htons(id);
    iph->frag_off = frag_off;
    iph->ttl = ttl;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = src_addr;
    iph->daddr = dest_addr;
    iph->tos = 0;
    iph->check = 0;

    /* calculate ip checksum */
    iph->check = leef_checksum((uint16_t *)iph, packet_size);

    /* send the packet */
    sktsin.sin_addr.s_addr = dest_addr;
    sktsin.sin_family = AF_INET;
    sktsin.sin_port = 0;
    int sent = sendto(handle->send_socket,
                      packet_buff, packet_size,
                      0,
                      (struct sockaddr *)&sktsin,
                      sizeof(struct sockaddr));
    if(sent > 0) {
      __sync_fetch_and_add(&leef_txpackets, 1);
      __sync_fetch_and_add(&leef_txbytes, packet_size + ETH_HLEN);
    }
    return sent;
}

int leef_send_udp_data(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id,
                      uint16_t data_size, uint8_t *data)
{
    static uint8_t typical_ttls[] = {64, 128};
    uint8_t ttl = typical_ttls[leef_rand() % sizeof(typical_ttls)] - (leef_rand() % 5);
    uint16_t frag_off = 0x40; /* don't fragment */
    return leef_send_raw_udp(handle,
                      src_addr, dest_addr,
                      src_port, dest_port,
                      id,
                      frag_off, ttl,
                      data_size, data);
}

int leef_send_raw_tcp2(struct leef_handle *handle,
                       uint32_t src_addr, uint32_t dest_addr,
                       uint16_t src_port, uint16_t dest_port,
                       uint32_t id, uint32_t seq, uint32_t ack_seq,
                       uint8_t flags,
                       uint16_t data_size, uint8_t *data)
{
    static uint16_t typical_windows[] = {5840, 8192, 16384, 65535};
    static uint8_t typical_ttls[] = {64, 128};

    uint8_t ttl = typical_ttls[leef_rand() % sizeof(typical_ttls)] - (rand() % 5);
    uint16_t window = typical_windows[leef_rand() % (sizeof(typical_windows) / 2)];
    uint16_t frag_off = 0x40; /* don't fragment */

    return leef_send_raw_tcp(handle,
                             src_addr, dest_addr,
                             src_port, dest_port,
                             id, seq, ack_seq,
                             frag_off, flags,
                             window, ttl,
                             0, NULL,
                             data_size, data);
}

int leef_send_tcp_syn(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id, uint32_t seq,
                      int use_tcp_options)
{
    static uint16_t typical_windows[] = {5840, 8192, 16384, 65535};
    static uint8_t typical_ttls[] = {64, 128};

    uint8_t ttl = typical_ttls[leef_rand() % sizeof(typical_ttls)] - (leef_rand() % 5);
    uint16_t window = typical_windows[leef_rand() % (sizeof(typical_windows) / 2)];
    uint16_t frag_off = 0x40; /* don't fragment */

    static uint8_t typical_options[7][12] = {
        { 0x02, 0x04, 0x05, 0xB4, 0x01, 0x03, 0x03, 0x00, 0x01, 0x01, 0x04, 0x02 },
        { 0x02, 0x04, 0x05, 0x70, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02 },
        { 0x02, 0x04, 0x05, 0xAC, 0x01, 0x03, 0x03, 0x02, 0x01, 0x01, 0x04, 0x02 },
        { 0x02, 0x04, 0x05, 0xA0, 0x01, 0x03, 0x03, 0x02, 0x01, 0x01, 0x04, 0x02 },
        { 0x02, 0x04, 0x05, 0xB4, 0x01, 0x01, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00 },
        { 0x02, 0x04, 0x05, 0xA0, 0x01, 0x01, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00 },
        { 0x02, 0x04, 0x05, 0xAC, 0x01, 0x01, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00 }
    };
    static uint8_t typical_options_size[7] = { 12, 12, 12, 12, 8, 8, 8 };

    uint8_t tcp_options_size = 0;
    uint8_t *tcp_options = NULL;
    if(use_tcp_options) {
        int option_id = leef_rand() % sizeof(typical_options_size);
        tcp_options_size = typical_options_size[option_id];
        tcp_options = typical_options[option_id];
    }

    return leef_send_raw_tcp(handle,
                             src_addr, dest_addr,
                             src_port, dest_port,
                             id, seq, 0,
                             frag_off, TCP_SYN,
                             window, ttl,
                             tcp_options_size, tcp_options,
                             0, NULL);
}

int leef_send_tcp_ack(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id, uint32_t seq, uint32_t ack_seq)
{
    return leef_send_raw_tcp2(handle,
                              src_addr, dest_addr,
                              src_port, dest_port,
                              id, seq, ack_seq,
                              TCP_ACK,
                              0, NULL);
}

const char *leef_name_tcp_flags(leef_sniffed_packet *packet)
{
    static char name[8];
    int pos = 0;
    if(packet->in_ip.tcp->syn == 1)
        name[pos++] = 'S';
    if(packet->in_ip.tcp->rst == 1)
        name[pos++] = 'R';
    if(packet->in_ip.tcp->fin == 1)
        name[pos++] = 'F';
    if(packet->in_ip.tcp->psh == 1)
        name[pos++] = 'P';
    if(packet->in_ip.tcp->ack == 1)
        name[pos++] = 'A';
    if(packet->in_ip.tcp->urg == 1)
        name[pos++] = 'U';
    name[pos] = 0;
    return name;
}

uint32_t leef_resolve_hostname(const char *hostname)
{
    struct hostent *he;
    he = gethostbyname(hostname);
    if(!he)
        return leef_string_to_addr(hostname);
    else {
        uint32_t addr = *(uint32_t *)he->h_addr;
        return addr;
    }
}

uint32_t leef_string_to_addr(const char *str)
{
    in_addr_t addr;
    if((addr = inet_addr(str)) == (unsigned long)-1)
        return 0;
    return (uint32_t)addr;
}

char *leef_addr_to_string(uint32_t addr)
{
    return inet_ntoa(*(struct in_addr*)&addr);
}

uint32_t leef_get_ticks() {
    static unsigned long firstTick = 0;
    struct timeval tv;
    gettimeofday(&tv, 0);
    if(!firstTick)
        firstTick = tv.tv_sec;
    return ((tv.tv_sec - firstTick) * 1000) + (tv.tv_usec / 1000);
}

int64_t leef_proc_read_int64(const char *path)
{
    FILE *fp = fopen(path, "r");
    char buf[32];
    if(fp) {
        fgets(buf, 32, fp);
        fclose(fp);
        return atoll(buf);
    }
    return -1;
}

int64_t leef_if_tx_packets(const char *devname)
{
    char path[128];
    sprintf(path, "/sys/class/net/%s/statistics/tx_packets", devname);
    return leef_proc_read_int64(path);
}

int64_t leef_if_tx_dropped(const char *devname)
{
    char path[128];
    sprintf(path, "/sys/class/net/%s/statistics/tx_dropped", devname);
    return leef_proc_read_int64(path);
}

int64_t leef_if_tx_bytes(const char *devname)
{
    char path[128];
    sprintf(path, "/sys/class/net/%s/statistics/tx_bytes", devname);
    return leef_proc_read_int64(path);
}

int64_t leef_if_rx_packets(const char *devname)
{
    char path[128];
    sprintf(path, "/sys/class/net/%s/statistics/rx_packets", devname);
    return leef_proc_read_int64(path);
}

int64_t leef_if_rx_dropped(const char *devname)
{
    char path[128];
    sprintf(path, "/sys/class/net/%s/statistics/rx_dropped", devname);
    return leef_proc_read_int64(path);
}

int64_t leef_if_rx_bytes(const char *devname)
{
    char path[128];
    sprintf(path, "/sys/class/net/%s/statistics/rx_bytes", devname);
    return leef_proc_read_int64(path);
}

uint32_t leef_if_ipv4(const char *devname)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, devname, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    return *(uint32_t *)(&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

uint16_t leef_random_dst_syn_port()
{
    static uint16_t common_ports[10] = { 21, 22, 23, 25, 80, 110, 143, 443, 3306, 8080 };
    uint32_t dest_port = leef_random_dst_port();
    if(dest_port > 32768)
        dest_port = common_ports[dest_port % 10];
    return dest_port;
}

