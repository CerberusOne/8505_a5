/*------------------------------------------------------------------------------
# SOURCE FILE: 		epoll.cpp
#
# PROGRAM:  		COMP8005 - Assignment 3
#
# FUNCTIONS:  int createEpollFd - creates an epoll fd
#             void addEpollSocket - adds a socket to epoll
#             int waitForEpollEvent - wait for an epoll event
#
# DATE:			Apr 6, 2018
#
# DESIGNER:		Benedict Lo
# PROGRAMMER:	Benedict Lo
#
# NOTES:		Epoll wrappers
#
------------------------------------------------------------------------------*/
#include "epoll.h"

#define MAX_EPOLL_EVENTS 64

/*------------------------------------------------------------------------------
# FUNCTIONS: createEpollFd
#
# DATE:			Apr 6, 2018
#
# DESIGNER:		Benedict Lo
# PROGRAMMER:	Benedict Lo
#
# RETURNS: file descriptor that was created
#
# NOTES:		Creates an epoll file descriptor
#
------------------------------------------------------------------------------*/
int createEpollFd(){
  int fd;
  if ((fd = epoll_create1(0)) == -1) {
      perror("epoll_create1");
  }
  return fd;
}

/*------------------------------------------------------------------------------
# FUNCTIONS: createEpollFd
#
# DATE:			Apr 6, 2018
#
# DESIGNER:		Benedict Lo
# PROGRAMMER:	Benedict Lo
#
# PARAMETER: const int epollfd - epoll file descriptor
#            const int sock - socket being added to epoll
#            struct epoll_event *ev - an epoll event
#
# RETURNS: VOID
#
# NOTES:		Add a socket for epoll to listen to
#
------------------------------------------------------------------------------*/
void addEpollSocket(const int epollfd, const int sock, struct epoll_event *ev) {
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, ev) == -1) {
        perror("epoll_ctl");
    }
}

/*------------------------------------------------------------------------------
# FUNCTIONS: waitForEpollEvent
#
# DATE:			Apr 6, 2018
#
# DESIGNER:		Benedict Lo
# PROGRAMMER:	Benedict Lo
#
# PARAMETER: const int epollfd - epoll file descriptor
#            const int sock - socket being added to epoll
#            struct epoll_event *ev - an epoll event
#
# RETURNS: file descriptor with event
#
# NOTES:		Add a socket for epoll to listen to
#
------------------------------------------------------------------------------*/
int waitForEpollEvent(const int epollfd, struct epoll_event *events) {
    int ev;
    if ((ev = epoll_wait(epollfd, events, MAX_EPOLL_EVENTS, -1)) == -1) {
        if (errno == EINTR) {
            return 0;
        }
        perror("epoll_wait");
    }
    return ev;
}


/*
//splice from one file descriptor to another
void spliceTo(int source, int destination, int pipefd[2]){
    int getBytes;
    int writeBytes;

    while(1) {
        //move bytes from source fd to pipe
        if((getBytes = splice(source, 0, pipefd[1], 0, USHRT_MAX, SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK)) == -1 && errno != EAGAIN) {
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
            writeBytes = splice(pipefd[0], 0, destination, 0, getBytes, SPLICE_F_MOVE | SPLICE_F_MORE | SPLICE_F_NONBLOCK);

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

void NewConnection(int socket, int epollfd){
    struct epoll_event event;
    socklen_t sin_size;
    struct sockaddr_storage their_addr;
    int clientsocket;
    while(1){
        sin_size = sizeof(struct sockaddr_storage);
        if((clientsocket = accept(socket, (struct sockaddr*)&their_addr, &sin_size)) == -1){
            if((errno == EAGAIN) || (errno == EWOULDBLOCK)){
                break;
                //no more connections
            } else {
                perror("accept");
                break;
            }
        }
        setNonBlocking(clientsocket);
        event.events = EPOLLIN | EPOLLET | EPOLLOUT;
        event.data.fd = clientsocket;
        addEpollSocket(epollfd, clientsocket, &event);
    }
}*/
