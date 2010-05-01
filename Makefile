all:
	g++ -O2 -o l7-filter l7-classify.cpp l7-queue.cpp l7-conntrack.cpp l7-filter.cpp -L /usr/local/lib/ -lnetfilter_conntrack -lnetfilter_queue -pthread
clean:
	rm l7-filter
