#ifndef PORTKNOCKING_H
#define PORTKNOCKING_H

#define TCP "tcp and ("
#define OR " || "
#define PORTS "port"
#define END ")"
#define FILTERAMOUNT 2
#define IPTABLES(ip,protocol,port) "iptables -I INPUT -p " protocol " -s " ip " --dport " port " -j ACCEPT"
#define TURNOFF(ip,protocol,port) "iptables -D INPUT -p " protocol "  -s " ip " --dport " port " -j ACCEPT"
#include "libpcap.h"

struct filter{
    int amount;
    const char *port[FILTERAMOUNT];
    unsigned short port_short[FILTERAMOUNT];
    unsigned short port_ushort[FILTERAMOUNT];
    char targetip[BUFSIZE];
    char localip[BUFSIZE];
    int pattern[FILTERAMOUNT];
};

struct filter InitFilter(char *target, char *local);
void PrintFilter(struct filter Filter);
void CreateFilter(struct filter Filter, char *buffer);
void PortKnocking(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet, bool send, struct filter Filter);
void SendPattern(unsigned char *data, struct filter Filter);

#endif
