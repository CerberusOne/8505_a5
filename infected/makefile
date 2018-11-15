backdoor: main.c  ../src/inotify.c ../src/epoll.c ../src/libpcap.c ../src/encrypt_utils.c ../src/socketwrappers.c ../src/covert_wrappers.c
	gcc -g -o backdoor main.c ../src/libpcap.c ../src/inotify.c ../src/epoll.c ../src/encrypt_utils.c ../src/socketwrappers.c ../src/covert_wrappers.c -lpcap -lcrypto -pthread

clean:
	rm -f *.o backdoor
	rm -f .results .cmd.sh
