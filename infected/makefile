main: main.c ../src/inotify.c ../src/portknocking.c ../src/libpcap.c ../src/encrypt_utils.c ../src/socketwrappers.c ../src/covert_wrappers.c
	gcc -g -o backdoor main.c ../src/inotify.c ../src/libpcap.c ../src/portknocking.c ../src/encrypt_utils.c ../src/socketwrappers.c ../src/covert_wrappers.c -lpcap -lcrypto

clean:
	rm -f *.o backdoor
	rm -f .results .cmd.sh
