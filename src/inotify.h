#IFNDEF INOTIFY_H
#define INOTIFY_H

#include <sys/inotify.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "epoll.h"

#define EVENT_SIZE (sizeof (struct inotify_event))
#define BUFLEN (1024 * (EVENT_SIZE + 16))

int watch_directory(char *directory, char *file);
int initInotify();
int addWatch(int socket, char *directory);


#endif
