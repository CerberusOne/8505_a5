#include "inotify.h"

int initInotify(){
    int socket;
    if((socket = inotify_init1(IN_NONBLOCK)) < 0){
        perror("Could not initilize inotify");
        exit(1);
    }
    return socket;
}

int addWatch(int socket, char *directory){
    int watch;
    if((watch = inotify_add_watch(socket, directory, IN_MODIFY)) < 0){
        perror("Could not iniitilize watch descriptor");
    }
    return watch;
}

int watch_directory(char *directory, char *file){
    int socket, watch, epollfd;
    struct epoll_event event;
    struct epoll_event *events;
    char buffer[BUFLEN];
    int k, len;

    socket = initInotify();
    watch = addWatch(socket, directory);
    epollfd = createEpollFd();

    event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    event.data.fd = socket;
    addEpollSocket(epollfd, socket, &event);
    events = calloc(64, sizeof(event));
    while(1){
        int ret = waitForEpollEvent(epollfd, events);
        for(int i = 0; i < ret; ++i){
            if(ret > 0){
                k =0;
                printf("Modificaitons were made to the file\n");
                len = read(socket, buffer, BUFLEN);
                while(k < len){
                    struct inotify_event *ievent;
                    ievent = (struct inotify_event *) &buffer[k];
                    printf("wd=%d, mask=%u cookie=%u len=%u\n", ievent->wd, ievent->mask, ievent->cookie, ievent->len);

                    if(ievent->len){
                        printf("name=%s\n", ievent->name);
                        if(strcmp(ievent->name, file) == 0){
                            printf("File was created exiting\n");
                            close(socket);
                            free(events);
                            exit(1);
                        }
                    }

                    k+= EVENT_SIZE + ievent->len;
                }
            } else if(ret < 0){
                perror("Epoll wait error");
                exit(1);
            }
        }
    }
    free(events);
}
