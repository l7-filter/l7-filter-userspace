PREFIX?=/usr/local
LIBDIR=${PREFIX}/lib/
BINDIR=${PREFIX}/bin/
MANDIR=${PREFIX}/share/man/man1/

CXX?=g++

all: l7-classify.o l7-queue.o l7-conntrack.o l7-filter.o util.o \
     l7-parse-patterns.o
	${CXX} -o l7-filter util.o l7-classify.o l7-queue.o l7-conntrack.o \
	l7-filter.o l7-parse-patterns.o -L ${LIBDIR} \
	-lnetfilter_conntrack -lnetfilter_queue -pthread
l7-classify.o: l7-classify.cpp l7-classify.h l7-queue.h util.h
	${CXX} -O2 -c l7-classify.cpp
l7-queue.o: l7-queue.cpp l7-queue.h l7-conntrack.h util.h
	${CXX} -O2 -c l7-queue.cpp
l7-conntrack.o: l7-conntrack.cpp l7-conntrack.h l7-classify.h l7-queue.h util.h
	${CXX} -O2 -c l7-conntrack.cpp
l7-filter.o: l7-filter.cpp l7-conntrack.h l7-queue.h l7-classify.h util.h
	${CXX} -O2 -c l7-filter.cpp
l7-parse-patterns.o: l7-parse-patterns.cpp l7-parse-patterns.h
	${CXX} -O2 -c l7-parse-patterns.cpp
util.o: util.cpp util.h
	${CXX} -O2 -c util.cpp
clean:
	rm l7-filter *.o
install:
	mkdir -p ${MANDIR} ${BINDIR}
	cp l7-filter ${BINDIR}
	cp l7-filter.1 ${MANDIR}
test:
	@echo "PREFIX is ${PREFIX}"
	@echo "LIBDIR is ${LIBDIR}"
	@echo "BINDIR is ${BINDIR}"
	@echo "MANDIR is ${MANDIR}"
	@echo "make will build using ${CXX}"

