#include <stdio.h>
#include <signal.h>
#include "leef.h"

int running = 1;
uint32_t interface_addr;

void signal_handler(int sig) {
    running = 0;
}

uint32_t unwated_ips[100][2];
int unwated_ips_size = 0;

void add_unwanted_ip(const char *ip, int mask)
{
    unwated_ips[unwated_ips_size][0] = leef_string_to_addr(ip);
    unwated_ips[unwated_ips_size][1] = leef_net_mask(mask);
    unwated_ips_size++;
}

void build_unwated_ips_list()
{
    add_unwanted_ip("0.0.0.0", 8);
    add_unwanted_ip("127.0.0.0", 8);
    add_unwanted_ip("10.0.0.0", 8);
    add_unwanted_ip("172.16.0.0", 12);
    add_unwanted_ip("192.168.0.0", 16);
    add_unwanted_ip("224.0.0.0", 3);
    add_unwanted_ip("169.254.0.0", 16);
    add_unwanted_ip("240.0.0.0", 5);
}

int is_valid_ip(uint32_t addr)
{
    int i;
    if(addr == 0 || addr == 0xffffffff)
        return 0;
    for(i=0;i<unwated_ips_size;++i)
        if((addr & unwated_ips[i][1]) == unwated_ips[i][0])
            return 0;
    return 1;
}

int main(int argc, char **argv)
{
    signal(SIGTERM, &signal_handler);
    signal(SIGINT, &signal_handler);

    if(argc != 3) {
        printf("usage: %s <interface> <file>\n", argv[0]);
        return -1;
    }
    char *interface = argv[1];
    char *filename = argv[2];

    FILE *fout = fopen(filename, "a");
    if(!fout) {
        fprintf(stderr, "could not open out file\n");
        return -1;
    }

    struct leef_handle leef;
    if(!leef_init(&leef, interface, SNIFFING))
        return -1;
    leef_set_sniff_packet_size(&leef, 64);
    leef_sniffed_packet packet;
    interface_addr = leef_if_ipv4(interface);

    uint32_t last_ticks, ticks_now;
    last_ticks = leef_get_ticks();
    build_unwated_ips_list();
    unsigned long sniffed_packets = 0;
    int pps = 0;

    printf("sniffing SYN+ACK on %s, output to %s\n", interface, filename);
    char line[1024];
    while(running) {
        if(leef_sniff_next_packet(&leef, &packet, 50)) {
            if(packet.ip->protocol == IPPROTO_TCP &&
            packet.ip->daddr == interface_addr &&
            packet.in_ip.tcp->ack == 1 && packet.in_ip.tcp->syn == 1 && packet.in_ip.tcp->rst == 0 &&
            is_valid_ip(packet.ip->saddr)) {
                sprintf(line, "%s:%d\n", leef_addr_to_string(packet.ip->saddr), (int)packet.in_ip.tcp->source);
                fputs(line, fout);
                fflush(fout);
                sniffed_packets++;
                pps++;
            }
        }

        ticks_now = leef_get_ticks();
        if(ticks_now - last_ticks >= 1000) {
            printf("packets: %d pps     total: %ul\n", pps, sniffed_packets);
            pps = 0;
            last_ticks = ticks_now;
        }
    }

    fclose(fout);
    return 0;
}
