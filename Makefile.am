# Created by Daniel Black <dragonheart@gentoo.org> for the l7-filter projects
#
EXTRA_DIST = sample-l7-filter.conf l7-filter.init l7-filter-userspace-0.10-protocols.patch l7-filter-userspace-0.10-quiet.patch TODO BUGS README l7-classify.h l7-conntrack.h l7-parse-patterns.h l7-queue.h util.h

bin_PROGRAMS = l7-filter

AM_CXXFLAGS = $(NFNETLINK_CFLAGS)

l7_filter_SOURCES = l7-classify.cpp l7-queue.cpp l7-conntrack.cpp  l7-filter.cpp l7-parse-patterns.cpp  util.cpp
l7_filter_LDADD = $(NFNETLINK_LIBS)

dist_man_MANS = l7-filter.1
