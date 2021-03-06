/*
 * =====================================================================================
 *
 *       Filename:  covert_wrappers.h
 *
 *    Description:  Wrapper functions for covert communications
 *
 *        Version:  1.0
 *        Created:  05/09/2018 05:28:00 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Aing Ragunathan
 *
 * =====================================================================================
 */
#ifndef COVERT_WRAPPERS_H
#define COVERT_WRAPPERS_H

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include "encrypt_utils.h"
#include "libpcap.h"
#include <netinet/udp.h>
#include <netinet/in.h>
#include <time.h>

#define _BSD_SOURCE
#define BUFSIZE 1024



struct send_tcp {
    struct iphdr ip;
    struct tcphdr tcp;
    unsigned char buffer[BUFSIZE + 16];     //payload size plus 16 bytes for encryption
} send_tcp;

struct recv_tcp {
    struct iphdr ip;
    struct tcphdr tcp;
    char buffer[BUFSIZE];
} recv_tcp;

struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
} pseudo_header;

struct upseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

char covert_udp_recv(char *sip, int sport, bool ttl, bool tos, bool ipid) ;
void covert_udp_send_data(char *sip, char *dip, unsigned short sport, unsigned short dport, char* data, int covert_channel);
void covert_udp_send(char *sip, char *dip, unsigned short sport, unsigned short dport, unsigned char* data, int covert_channel);
void recv_results(char* sip, unsigned short sport, char* filename,bool tcp);
void send_results(char *sip, char *dip, unsigned short sport, unsigned short dport, char *filename,bool tcp);
int rand_delay(int delay);
void covert_send(char *sip, char *dip, unsigned short sport, unsigned short dport, unsigned char* data, int covert_channel);
char covert_recv(char *sip, unsigned short sport, int ipid, int seq, int ack, int tos);
int generate_rand();
unsigned int host_convert(char* ip);
unsigned short checksum(unsigned short* ptr, int nbytes);
unsigned short csum(unsigned short *ptr,int nbytes);
#endif
