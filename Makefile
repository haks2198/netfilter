all : netfilter

netfilter:clean
	gcc -o netfilter main.cpp -lnetfilter_queue
clean:
	rm -f netfilter