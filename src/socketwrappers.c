#define _GNU_SOURCE

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
#include <limits.h>
#include "socketwrappers.h"
#include <fcntl.h>


#define MAXCONNECTION 62

void setNonBlocking(int fd){
    fcntl(fd, F_SETFL, O_NONBLOCK);
}

void sigHandler(int s){
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

struct addrinfo setHints(int family, int socktype, int flags){
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = family; //IPV4
    hints.ai_socktype = socktype; //TCP
    hints.ai_flags = flags;

    return hints;
}

//node is the hostname to connect to
//service is the port number
//hints points to a addrinfo struct
struct addrinfo setAddrInfo(const char* address,const char *port, struct addrinfo hints){
    int status;
    struct addrinfo *servinfo;

    if((status = getaddrinfo(address, port, &hints, &servinfo)) != 0){
        perror("getaddrinfo");
        exit(1);
    }
    return(*servinfo);
    //freeaddrinfo(servinfo);
}

int setBind(int fd, struct addrinfo *p){
    int r;
    if((r = bind(fd, p->ai_addr, p->ai_addrlen)) == -1){
        perror("bind");
        exit(1);
        return -1;
    }
    return r;
}

void setListen(int fd){
    if((listen(fd, MAXCONNECTION)) == -1){
        perror("listen");
        exit(1);
    }
}

int makeConnect(const char *address, const char *port){
    struct addrinfo hints;
    struct addrinfo *servinfo;
    struct addrinfo *p;
    int fd;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if((getaddrinfo(address, port, &hints, &servinfo)) != 0){
        perror("getaddrinfo");
        exit(1);
    }

    for(p = servinfo; p != NULL; p->ai_next){
        if((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("client: socket");
            continue;
        }
        if((connect(fd, p->ai_addr, p->ai_addrlen)) == -1){
            close(fd);
            perror("client:bind");
            continue;
        }
        break;
    }

    freeaddrinfo(servinfo);

    //set_non_blocking(fd);

    return fd;
}


int makeBind(const char *port){
    struct addrinfo hints;
    struct addrinfo *servinfo;
    struct addrinfo *p;
    int fd;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if((getaddrinfo(NULL, port, &hints, &servinfo)) != 0){
        perror("getaddrinfo");
        exit(1);
    }

    for(p = servinfo; p != NULL; p->ai_next){
        if((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("server: socket");
            continue;
        }
        int yes = 1;
        if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
            perror("setsockopt");
        }
        if((bind(fd, p->ai_addr, p->ai_addrlen)) == -1){
            close(fd);
            perror("server:bind");
            continue;
        }
        break;
    }
    if(p == NULL){
        perror("Could not bind");
    }
    freeaddrinfo(servinfo);

    //set_non_blocking(fd);

    return fd;
}

int Accept(int fd, struct sockaddr_storage *addr){
    int r;
    socklen_t len = sizeof(struct sockaddr_storage);
    if((r = accept(fd,(struct sockaddr*)addr, &len)) != -1){
        perror("accept");
    }
    return r;
}

int recvBytes(int fd, char *buff){
    int bytesread;
    if((bytesread = recv(fd, buff, sizeof(buff), 0)) != -1){
        if(errno != EAGAIN){
            perror("read");
        }
    }
    return bytesread;
}

int sendBytes(int fd, char *buff){
    int bytesrecv;
    if((bytesrecv = send(fd, buff, sizeof(buff), 0)) != -1){
        perror("recv");
    }
    return bytesrecv;
}

void spliceTo(int source, int destination, int pipefd[2]){
    int getBytes;
    int writeBytes;

    while(1) {
        //move bytes from source fd to pipe
        if((getBytes = splice(source, 0, pipefd[1], 0, USHRT_MAX, SPLICE_F_MOVE | SPLICE_F_MORE)) == -1 && errno != EAGAIN) {
            perror("getting splice error");
        }
        if(errno==EAGAIN){
            continue;
        }
        if((getBytes <= 0) && errno != EAGAIN ) {
            return;
        }

        printf("bytes read: %d\n", getBytes);

        //write bytes from pipe to destination fd
        do{
            writeBytes = splice(pipefd[0], 0, destination, 0, getBytes, SPLICE_F_MOVE | SPLICE_F_MORE);

            if(writeBytes <= 0) {
                if(writeBytes == -1 && errno != EAGAIN) {
                    perror("writing splice error");
                }
                break;
            }

            printf("wrote: %d\n", writeBytes);
            getBytes -= writeBytes;
        } while(getBytes);
    }
}
