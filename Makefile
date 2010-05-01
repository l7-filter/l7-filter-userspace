all: l7-classify.o l7-queue.o l7-conntrack.o l7-filter.o util.o \
     l7-parse-patterns.o
	g++ -o l7-filter util.o l7-classify.o l7-queue.o l7-conntrack.o \
	l7-filter.o l7-parse-patterns.o -L /usr/local/lib/ \
	-lnetfilter_conntrack -lnetfilter_queue -pthread
l7-classify.o: l7-classify.cpp l7-classify.h l7-queue.h util.h
	g++ -O2 -c l7-classify.cpp
l7-queue.o: l7-queue.cpp l7-queue.h l7-conntrack.h util.h
	g++ -O2 -c l7-queue.cpp
l7-conntrack.o: l7-conntrack.cpp l7-conntrack.h l7-classify.h l7-queue.h util.h
	g++ -O2 -c l7-conntrack.cpp
l7-filter.o: l7-filter.cpp l7-conntrack.h l7-queue.h l7-classify.h util.h
	g++ -O2 -c l7-filter.cpp
l7-parse-patterns.o: l7-parse-patterns.cpp l7-parse-patterns.h
	g++ -O2 -c l7-parse-patterns.cpp
util.o: util.cpp util.h
	g++ -O2 -c util.cpp
clean:
	rm l7-filter *.o
install:
	cp l7-filter /usr/local/bin/
	cp l7-filter.1 /usr/share/man/man1/
