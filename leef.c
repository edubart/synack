#include "leef.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int send_socket = -1;
int sniff_socket = -1;
int sniff_size = SNIFF_BUFFER_SIZE;

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

int leef_init()
{
    sniff_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sniff_socket == -1) {
        fprintf(stderr, "Unable to create the raw socket! (Are you root?)");
        return 0;
    }

    send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(send_socket == -1) {
        fprintf(stderr, "Unable to create the raw socket! (Are you root?)");
        return 0;
    }

    int hdrincl_on = 1;
    if(setsockopt(send_socket, IPPROTO_IP, IP_HDRINCL, (char *)&hdrincl_on, sizeof(hdrincl_on)) == -1) {
        fprintf(stderr, "Unable to set IP_HDRINCL option!");
        return 0;
    }
    return 1;
}

void leef_terminate()
{
    if(send_socket != -1) {
        close(send_socket);
    }
    if(sniff_socket != -1) {
        close(sniff_socket);
    }
}


void leef_set_sniff_packet_size(int size)
{
    sniff_size = size;
}

int leef_sniff_next_packet(struct leef_sniffed_packet *packet)
{
    static socklen_t fromlen = sizeof(struct sockaddr_ll);
    struct sockaddr_ll fromaddr;
    struct ifreq ifr;
    fd_set set;
    struct timeval tv;
    int ss;

    FD_ZERO(&set);
    FD_SET(sniff_socket, &set);

    tv.tv_sec = 0;
    tv.tv_usec = 50000;

    do {
        ss = select(sniff_socket + 1, &set, 0, 0, &tv);
    } while ((ss < 0) && (errno == EINTR));

    if(FD_ISSET(sniff_socket, &set)) {
        if(recvfrom(sniff_socket, packet->buf, sniff_size, 0, (struct sockaddr *)&fromaddr, &fromlen) == 0) {
            return 0;
        }

        ifr.ifr_ifindex = fromaddr.sll_ifindex;
        ioctl(sniff_socket, SIOCGIFNAME, &ifr);

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
        } else if(packet->ip->protocol == IPPROTO_UDP) {
            packet->in_ip.udp = (struct udphdr *) ((char *) packet->ip + packet->ip->ihl * 4);
        }
        return 1;
    }
    return 0;
}


int leef_send_raw_tcp(uint32_t src_addr, uint32_t dest_addr,
                uint16_t src_port, uint16_t dest_port,
                uint32_t id, uint32_t seq, uint32_t ack_seq, uint8_t flags, uint16_t window, uint8_t ttl,
                uint16_t data_size, uint8_t *data)
{
    static uint8_t buffer[SEND_BUFFER_SIZE];
    uint16_t packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_size;
    struct iphdr ip;
    struct tcphdr tcp;

    bzero(&ip, sizeof(struct iphdr));
    bzero(&tcp, sizeof(struct tcphdr));

    /* setup ip header */
    ip.version = 4;
    ip.ihl = 5;
    ip.tot_len = htons(packet_size);
    ip.id = htons(id);
    ip.frag_off = 0x40; /* don't fragment */
    ip.ttl = ttl;
    ip.protocol = IPPROTO_TCP;
    ip.saddr = src_addr;
    ip.daddr = dest_addr;

    /* setup tcp header */
    tcp.source = htons(src_port);
    tcp.dest = htons(dest_port);
    tcp.seq = htonl(seq);
    tcp.ack_seq = htonl(ack_seq);
    tcp.doff = sizeof(struct tcphdr) / 4;
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
    pseudo.len = htons(sizeof(struct tcphdr) + data_size);

    memcpy(buffer, &pseudo, sizeof(pseudo));
    memcpy(buffer + sizeof(pseudo), (uint8_t *)&tcp, sizeof(struct tcphdr));
    memcpy(buffer + sizeof(pseudo) + sizeof(struct tcphdr), data, data_size);
    tcp.check = leef_checksum((uint16_t *)buffer, sizeof(pseudo) + sizeof(struct tcphdr) + data_size);

    /* build packet buffer and calculate ip checksum */
    memcpy(buffer, &ip, sizeof(struct iphdr));
    memcpy(buffer + sizeof(struct iphdr), &tcp, sizeof(struct tcphdr));
    memcpy(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr), data, data_size);
    ip.check = leef_checksum((uint16_t *)buffer, packet_size);
    memcpy(buffer, &ip, sizeof(struct iphdr));

    /* send the packet */
    struct sockaddr_in sktsin;
    sktsin.sin_addr.s_addr = dest_addr;
    sktsin.sin_family = AF_INET;
    sktsin.sin_port = 0;
    return sendto(send_socket, buffer, packet_size, 0, (struct sockaddr *)&sktsin, sizeof(struct sockaddr));
}

int leef_send_tcp_syn(uint32_t src_addr, uint32_t dest_addr, uint16_t src_port, uint16_t dest_port, uint32_t id, uint32_t seq)
{
    return leef_send_raw_tcp(src_addr, dest_addr, src_port, dest_port, id, seq, 0, TCP_SYN, 5840, 64, 0, NULL);
}

int leef_send_tcp_ack(uint32_t src_addr, uint32_t dest_addr, uint16_t src_port, uint16_t dest_port, uint32_t id, uint32_t seq, uint32_t ack_seq)
{
    return leef_send_raw_tcp(src_addr, dest_addr, src_port, dest_port, id, seq, ack_seq, TCP_ACK, 5840, 64, 0, NULL);
}

uint32_t leef_resolve_hostname(const char *hostname)
{
    unsigned long addr;
    struct hostent *he;
    he = gethostbyname(hostname);
    if(!he) {
        if((addr = inet_addr(hostname)) == (unsigned long)-1)
            return 0;
    } else {
        addr = *(unsigned long *)he->h_addr;
    }
    return addr;
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
