/*
    Raw UDP sockets
    Silver Moon (m00n.silv3r@gmail.com)
*/
#include<stdio.h> //for printf
#include<string.h> //memset
#include<sys/socket.h>    //for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/in.h>
#include<arpa/inet.h>

#define BUFSIZE 1024

/*
    96 bit (12 bytes) pseudo header needed for udp header checksum calculation
*/

struct send_udp {
    struct iphdr ip;
    struct udphdr udp;
    unsigned char buffer[BUFSIZE + 16];
} send_udp;

struct recv_udp {
    struct iphdr ip;
    struct udphdr udp;
    unsigned char buffer[BUFSIZE];
} recv_udp;

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
} upseudo_header;

/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes);

int main (void){
    int s;
    if((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1){
        perror("Failed to create raw socket");
        exit(1);
    }

    //Datagram to represent the packet
    char datagram[4096] , source_ip[32] , *data , *pseudogram;
    struct send_udp packet;

    //zero out the packet buffer
    memset (datagram, 0, 4096);

    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;

    //UDP header
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));

    struct sockaddr_in sin;
    struct pseudo_header psh;

    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

    //some address resolution
    strcpy(source_ip , "192.168.0.115");

    sin.sin_family = AF_INET;
    sin.sin_port = htons(8505);
    sin.sin_addr.s_addr = inet_addr ("192.168.0.118");

    packet.ip.ihl = 5;
    packet.ip.ihl = 4;
    packet.ip.version = 4;
    packet.ip.tos = 0;
    packet.ip.tot_len = htons(40);
    packet.ip.id = 0;
    packet.ip.frag_off = 0;
    packet.ip.ttl = 64;
    packet.ip.protocol = IPPROTO_IDP;
    packet.ip.check = 0;
    packet.ip.saddr = inet_addr(source_ip);
    packet.ip.daddr = sin.sin_addr.s_addr;
    packet.ip.check = csum ((unsigned short *) &send_udp.ip, 20);

    packet.udp.source = htons (8505);
    packet.udp.dest = htons(8505);
    packet.udp.len = htons(8 + BUFSIZE);
    packet.udp.check = 0;

    upseudo_header.source_address = inet_addr(source_ip);
    upseudo_header.dest_address = sin.sin_addr.s_addr;
    upseudo_header.placeholder = 0;
    upseudo_header.protocol = IPPROTO_UDP;
    upseudo_header.udp_length = htons(sizeof(struct udphdr) + BUFSIZE);

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));

    packet.udp.check = csum( (unsigned short*) pseudogram , psize);

    //loop if you want to flood :)
    //while (1)
    {
        //Send the packet
        if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror("sendto failed");
        }
        //Data send successfully
        else
        {
            printf ("Packet Send. Length : %d \n" , iph->tot_len);
        }
    }

    return 0;
}

unsigned short csum(unsigned short *ptr,int nbytes)
{
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
//Complete
