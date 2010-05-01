all: l7-classify.o l7-queue.o l7-conntrack.o l7-filter.o util.o
	g++ -O2 -o l7-filter util.o l7-classify.o l7-queue.o l7-conntrack.o l7-filter.o -L /usr/local/lib/ -lnetfilter_conntrack -lnetfilter_queue -pthread
l7-classify.o: l7-classify.cpp l7-classify.h l7-queue.h util.h
	g++ -c l7-classify.cpp
l7-queue.o: l7-queue.cpp l7-queue.h l7-conntrack.h util.h
	g++ -c l7-queue.cpp
l7-conntrack.o: l7-conntrack.cpp l7-conntrack.h l7-classify.h l7-queue.h util.h
	g++ -c l7-conntrack.cpp
l7-filter.o: l7-filter.cpp l7-conntrack.h l7-queue.h l7-classify.h util.h
	g++ -c l7-filter.cpp
util.o: util.cpp util.h
	g++ -c util.cpp
clean:
	rm l7-filter *.o
install:
	cp l7-filter /usr/local/bin/
