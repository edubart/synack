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

int leef_adjust_sniffed_packet_buffer(struct leef_sniffed_packet *packet)
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

uint16_t leef_checksum(uint16_t *ptr, int nbytes)
{
    uint32_t sum = 0;
    uint16_t oddbyte;

    sum = 0;
    while(nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1)
    {
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
    leef_srand();

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

int leef_sniff_next_packet(struct leef_handle *handle, struct leef_sniffed_packet *packet)
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
    tv.tv_usec = 50000;

    do {
        ss = select(handle->sniff_socket + 1, &set, 0, 0, &tv);
    } while ((ss < 0) && (errno == EINTR));

    if(FD_ISSET(handle->sniff_socket, &set)) {
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
    uint8_t buffer[SEND_BUFFER_SIZE];
    uint16_t packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_options_size + data_size;
    struct iphdr ip;
    struct tcphdr tcp;

    bzero(&ip, sizeof(struct iphdr));
    bzero(&tcp, sizeof(struct tcphdr));

    /* setup ip header */
    ip.version = 4;
    ip.ihl = 5;
    ip.tot_len = htons(packet_size);
    ip.id = htons(id);
    ip.frag_off = frag_off; /* don't fragment */
    ip.ttl = ttl;
    ip.protocol = IPPROTO_TCP;
    ip.saddr = src_addr;
    ip.daddr = dest_addr;

    /* setup tcp header */
    tcp.source = htons(src_port);
    tcp.dest = htons(dest_port);
    tcp.seq = htonl(seq);
    tcp.ack_seq = htonl(ack_seq);
    tcp.doff = (sizeof(struct tcphdr) + tcp_options_size) / 4;
    tcp.window = htons(window);

    if(flags & TCP_FIN)
        tcp.fin = 1;
    if(flags & TCP_SYN)
        tcp.syn = 1;
    if(flags & TCP_RST)
        tcp.rst = 1;
    if(flags & TCP_PUSH)
        tcp.psh = 1;
    if(flags & TCP_ACK)
        tcp.ack = 1;
    if(flags & TCP_URG)
        tcp.urg = 1;

    /* calculate tcp checksum */
    struct {
        uint32_t saddr, daddr;
        uint8_t res;
        uint8_t proto;
        uint16_t len;
    } pseudo;

    pseudo.saddr = ip.saddr;
    pseudo.daddr = ip.daddr;
    pseudo.res = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len = htons(sizeof(struct tcphdr) + tcp_options_size + data_size);

    memcpy(buffer, &pseudo, sizeof(pseudo));
    memcpy(buffer + sizeof(pseudo), (uint8_t *)&tcp, sizeof(struct tcphdr));
    memcpy(buffer + sizeof(pseudo) + sizeof(struct tcphdr), tcp_options, tcp_options_size);
    memcpy(buffer + sizeof(pseudo) + sizeof(struct tcphdr) + tcp_options_size, data, data_size);
    tcp.check = leef_checksum((uint16_t *)buffer, sizeof(pseudo) + sizeof(struct tcphdr) + tcp_options_size + data_size);

    /* build packet buffer and calculate ip checksum */
    memcpy(buffer, &ip, sizeof(struct iphdr));
    memcpy(buffer + sizeof(struct iphdr), &tcp, sizeof(struct tcphdr));
    memcpy(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr), tcp_options, tcp_options_size);
    memcpy(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_options_size, data, data_size);
    ip.check = leef_checksum((uint16_t *)buffer, packet_size);
    memcpy(buffer, &ip, sizeof(struct iphdr));

    /* send the packet */
    struct sockaddr_in sktsin;
    sktsin.sin_addr.s_addr = dest_addr;
    sktsin.sin_family = AF_INET;
    sktsin.sin_port = 0;
    return sendto(handle->send_socket,
                  buffer, packet_size,
                  0,
                  (struct sockaddr *)&sktsin,
                  sizeof(struct sockaddr));
}

int leef_send_raw_udp(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id,
                      uint16_t frag_off, uint8_t ttl,
                      uint16_t data_size, uint8_t *data)
{
    uint8_t buffer[SEND_BUFFER_SIZE];
    uint16_t packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + data_size;
    struct iphdr ip;
    struct udphdr udp;

    bzero(&ip, sizeof(struct iphdr));
    bzero(&udp, sizeof(struct udphdr));

    /* setup ip header */
    ip.version = 4;
    ip.ihl = 5;
    ip.tot_len = htons(packet_size);
    ip.id = htons(id);
    ip.frag_off = frag_off; /* don't fragment */
    ip.ttl = ttl;
    ip.protocol = IPPROTO_UDP;
    ip.saddr = src_addr;
    ip.daddr = dest_addr;

    /* setup udp header */
    udp.source = htons(src_port);
    udp.dest = htons(dest_port);
    udp.len = htons(sizeof(struct udphdr) + data_size);

    /* calculate udp checksum */
    struct {
        uint32_t saddr, daddr;
        uint8_t res;
        uint8_t proto;
        uint16_t len;
    } pseudo;

    pseudo.saddr = ip.saddr;
    pseudo.daddr = ip.daddr;
    pseudo.res = 0;
    pseudo.proto = IPPROTO_UDP;
    pseudo.len = udp.len;

    memcpy(buffer, &pseudo, sizeof(pseudo));
    memcpy(buffer + sizeof(pseudo), &udp, sizeof(struct udphdr));
    memcpy(buffer + sizeof(pseudo) + sizeof(struct udphdr), data, data_size);
    udp.check = leef_checksum((uint16_t *)buffer, sizeof(pseudo) + sizeof(struct udphdr) + data_size);

    /* build packet buffer and calculate ip checksum */
    memcpy(buffer, &ip, sizeof(struct iphdr));
    memcpy(buffer + sizeof(struct iphdr), &udp, sizeof(struct udphdr));
    memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), data, data_size);
    ip.check = leef_checksum((uint16_t *)buffer, packet_size);
    memcpy(buffer, &ip, sizeof(struct iphdr));

    /* send the packet */
    struct sockaddr_in sktsin;
    sktsin.sin_addr.s_addr = dest_addr;
    sktsin.sin_family = AF_INET;
    sktsin.sin_port = 0;
    return sendto(handle->send_socket,
                  buffer, packet_size,
                  0,
                  (struct sockaddr *)&sktsin,
                  sizeof(struct sockaddr));
}

int leef_send_udp_data(struct leef_handle *handle,
                      uint32_t src_addr, uint32_t dest_addr,
                      uint16_t src_port, uint16_t dest_port,
                      uint32_t id,
                      uint16_t data_size, uint8_t *data)
{
    static uint8_t typical_ttls[] = {64, 128};
    uint8_t ttl = typical_ttls[rand() % sizeof(typical_ttls)] - (rand() % 5);
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

    uint8_t ttl = typical_ttls[rand() % sizeof(typical_ttls)] - (rand() % 5);
    uint16_t window = typical_windows[rand() % (sizeof(typical_windows) / 2)];
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

    uint8_t ttl = typical_ttls[rand() % sizeof(typical_ttls)] - (rand() % 5);
    uint16_t window = typical_windows[rand() % (sizeof(typical_windows) / 2)];
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
        int option_id = rand() % sizeof(typical_options_size);
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

const char *leef_name_tcp_flags(struct leef_sniffed_packet *packet)
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

void leef_srand() {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    srand((tv.tv_sec * 1000) + (tv.tv_usec / 1000));
}

int leef_random_range(int min, int max) {
    if(min > max) {
        int tmp = max;
        max = min;
        min = tmp;
    }
    double range = max - min + 1;
    int ret = (min + ((int)((range * rand())/ (RAND_MAX+1.0))));
    return ret;
}

uint8_t leef_random_byte() {
    return (uint8_t)(rand() % 1 << 8);
}

uint16_t leef_random_u16() {
    return (uint16_t)(rand() % (1 << 16));
}

uint32_t leef_random_u32() {
    return (uint32_t)(leef_random_u16() << 16 | leef_random_u16());
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

int64_t leef_if_tx_bytes(const char *devname)
{
    char path[128];
    sprintf(path, "/sys/class/net/%s/statistics/tx_bytes", devname);
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

