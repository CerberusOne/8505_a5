#ifndef PORTKNOCKING_H
#define PORTKNOCKING_H

#include "main.h"


#define TCP "tcp and ("
#define OR " || "
#define PORTS " port "
#define END ")"
#define FILTERAMOUNT 3

struct filter{
    int amount;
    const char *port[FILTERAMOUNT];
    unsigned short port_short[FILTERAMOUNT];
};

struct filter InitFilter();
void CreateFilter(struct filter Filter, char *buffer);
void PortKnocking(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet, bool send, struct filter Filter);
void SendPattern(char *sip, char *dip, unsigned short sport, unsigned short dport, unsigned char *data, struct filter Filter);

#endif
