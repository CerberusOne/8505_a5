main: main.c ../src/epoll.c ../src/inotify.c ../src/libpcap.c ../src/encrypt_utils.c ../src/socketwrappers.c ../src/covert_wrappers.c
	gcc -g -o cnc main.c ../src/epoll.c ../src/inotify.c ../src/libpcap.c ../src/encrypt_utils.c ../src/socketwrappers.c ../src/covert_wrappers.c -lpcap -lcrypto

clean:
	rm -f *.o cnc
	rm -f .results .cmd.sh
