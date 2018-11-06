#ifndef SOCKETWRAPPERS_H
#define SOCKETWRAPPERS_H

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <signal.h>
#include <limits.h>


void setNonBlocking(int fd);
void sigHandler(int s);
struct addrinfo setHints(int family, int socktype, int flags);
struct addrinfo setAddrInfo(const char* address, const char *port, struct addrinfo hints);
int setBind(int fd, struct addrinfo *p);
void setListen(int fd);
int makeBind(const char *port);
int makeConnect(const char *address, const char *port);
int Accept(int fd, struct sockaddr_storage *addr);
int recvBytes(int fd, char *buff);
int readBytes(int fd, char *buff);
void spliceTo(int source, int destination, int pipefd[2]);
void NewConnection(int socket, int epollfd);
void spliceTo(int source, int destination, int pipefd[2]);

#endif
