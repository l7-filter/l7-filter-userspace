/*
  Functions and classes which track the conntracks for l7-filter.
  
  By Ethan Sommer <sommere@users.sf.net> and Matthew Strait 
  <quadong@users.sf.net>, (C) 2006-2007
  http://l7-filter.sf.net 

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version
  2 of the License, or (at your option) any later version.
  http://www.gnu.org/licenses/gpl.txt

  Based on ctnl_test.c from libnetfilter-conntrack 0.0.31 (C) 2005 by 
  Pablo Neira Ayuso <pablo@eurodev.net>
   and
  Based on nfqnl_test.c from libnetfilter-queue 0.0.12
*/

using namespace std;
#include <pthread.h>

#include <fstream>
#include <iostream>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <map>

#include "l7-conntrack.h"
#include "l7-queue.h"
#include "l7-classify.h"
#include "util.h"
#include "config.h"

extern "C" {
#include <linux/netfilter.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
}

static l7_conntrack* l7_connection_tracker;
static l7_queue* l7_queue_tracker;

// Configurable parameters
extern int verbosity;
extern int buflen;
extern int maxpackets;
extern string l7dir;
extern unsigned int markmask;
extern unsigned int maskfirstbit;
extern unsigned int masknbits;
extern int clobbermark;

static void handle_sigint(int s) {
  // was there a reason for this?  It just makes it crash on Ctrl-C for me.
  //delete l7_connection_tracker;
  exit(0);
}


//queue functions

#if 0
/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
  int id = 0;
  struct nfqnl_msg_packet_hdr *ph;
  u_int32_t mark,ifi; 
  int ret;
  char *data;
  
  ph = nfq_get_msg_packet_hdr(tb);
  if(ph){
    id = ntohl(ph->packet_id);
    printf("hw_protocol=0x%04x hook=%u id=%u ",
      ntohs(ph->hw_protocol), ph->hook, id);
  }
  
  mark = nfq_get_nfmark(tb);
  if (mark) printf("mark=%u ", mark);

  ifi = nfq_get_indev(tb);
  if(ifi) printf("indev=%u ", ifi);

  ifi = nfq_get_outdev(tb);
  if(ifi) printf("outdev=%u ", ifi);

  ret = nfq_get_payload(tb, &data);
  if (ret >= 0) printf("payload_len=%d ", ret);

  putchar('\n');

  return id;
}
#endif

static void * start_connection_tracking_thread(void *data) 
{
  l7_connection_tracker->start();
  pthread_exit(NULL);
}

static void * start_queue_thread(void * qnum) 
{
  int * queuenum = (int *)qnum;

  l7_queue_tracker->start(*queuenum);
  pthread_exit(NULL);
}

// Checks whether the given mask has all its 1's in a row
// and that it has enough room to work in
static int checkandparsemask(const unsigned int mask)
{
  int i = 0;
  masknbits = 0;

  // it can start with 0 or more 0's
  while((mask >> i)%2 == 0){
    i++;
    if(i >= 32) return false; // it's all zeros!
  }  

  maskfirstbit = i;

  // followed by 0 or more 1's
  while((mask >> i)%2 == 1){ 
    masknbits++;
    i++;
  } 
  if(masknbits < 2) return false; // need at least two bits to work with

  // the rest has to be all 0's
  for(; i < 32; i++)
    if((mask >> i)%2 == 1)
      return false;

  return true;
}

static void handle_cmdline(int & qnum, string & conffilename, 
  int argc, char ** argv)
{
  int dumb = 0; // whether to allow dumb things
  qnum = 0; // default
  buflen = 8*1500; //default (8 large packets worth)
  conffilename = ""; 
  const char *opts = "f:q:vh?sb:dn:p:m:c";

  int done = 0;
  while(!done)
  {
    char c;
    switch(c = getopt(argc, argv, opts))
    {
      case -1:
        done = 1;
        break;
      case 'f':
        conffilename = optarg;
        break;
      case 'p':
        l7dir = optarg;
        break;
      case 'q':
        qnum = strtol(optarg, 0, 10);
        if(qnum == LONG_MIN || qnum == LONG_MAX || qnum < 0 || qnum > 65535){
          cerr << "Queue number is out of range. Valid numbers are 0-65535.\n";
          exit(1);
        }
        break;
      case 'b':
        buflen = strtol(optarg, 0, 10);
        if(buflen == LONG_MIN || buflen == LONG_MAX || 
	   ((buflen < 1 || buflen > 65535) && !dumb)){
          cerr << "Buffer length is out of range or you gave me a non-number.\n"
            "Valid lengths are 0-65535. (65535 is an arbitrary limit. If you\n"
            "are sure you need more, use the -d switch before this one.)\n";
          exit(1);
        }
        break;
      case 'n':
        maxpackets = strtoll(optarg, 0, 10);
        // never allow maxpackets to be less than one.
        // Allow it to be outside of the range 3-16 only if -d is given
        if(maxpackets == LONG_MIN || maxpackets == LONG_MAX || maxpackets < 1 ||
           ((maxpackets < 3 || maxpackets > 16) && !dumb)){
          cerr << "The number of packets is out of range or you gave me a\n"
                  "non-number. Valid number are between 3 and 16. Or if you\n"
                  "give the -d option before this one, I'll allow any\n"
                  "positive integer.\n";
          exit(1);
        }
        break;
      case 'm':
	markmask = strtoll(optarg, 0, 0);
        if(errno == ERANGE){
          cerr << "You seem to have given me a bogus mask.\n";
          exit(1);
        }
	if(!checkandparsemask(markmask)){
          cerr<<"I can only handle masks in which the asserted bits are "
                "contiguous\n"
                "For example: 0x0000fff0, but not 0xf000f000.\n"
                "I also need at least two bits to work with.\n";
          exit(1);
        }
        break; 
      case 'c':
        clobbermark = 1;
        break;       
      case 'v':
        verbosity++;
        break;
      case 'd':
        dumb = 1;
        cout << "Allowing configurations that are probably ill-advised...\n";
        break;
      case 's':
        verbosity = -1;
        break;
      case 'h':
      case '?':
      default:
        cerr << 
          "l7-filter v" << VERSION <<
          ", (C) 2006-2007 Ethan Sommer, Matthew Strait\n"
          "l7-filter comes with ABSOLUTELY NO WARRANTY. This is free software\n"
          "and you may redistribute it under the terms of the GPLv2.\n"
          "\n"
          "Syntax: l7-filter -f configuration_file [options]\n"
          "\n"
          "Options are:\n"
          "-q queuenumber\tListen to the specified Netfilter queue\n"
          "-v\t\tBe verbose. Mutiple -v options increase the verbosity\n"
          "-s\t\tBe silent except in the case of warnings and errors\n"
          "-b bytes\tStore up to this many bytes of data per connection\n"
          "-n packets\tExamine up to this many packets per connection\n"
          "-p path\t\tLook for patterns in path instead of /etc/l7-protocols\n"
          "-m mask\t\tOnly pay look at and set the given bits of marks\n"
          "-c\t\tClobber existing marks instead of passing them unmodified\n"
          "-d\t\tAllow configurations that are probably ill-advised\n"
          "\n"
          "See also 'man l7-filter'\n";
        exit(1);
        break;
    }
  }

  if(conffilename == ""){
    cerr << "You must specify a configuration file.  Try 'l7-filter -h'\n";
    exit(1);
  }
}

// Checks if the specified module is loaded.  Returns 1 if yes, 0 if no.
static int check_for_module(string mod)
{
  ifstream pm("/proc/modules");
  if(!pm.is_open()){
    cerr << "What the...?  Failed to open /proc/modules!\n";
    return 0;
  }

  string line;
  while(!pm.eof()){
    getline(pm, line);
    if(line.substr(0, mod.size()) == mod)
      return 1;
  }
  
  return 0;
}

static void check_requirements()
{
  if(!check_for_module("ip_conntrack_netlink") && 
     !check_for_module("nf_conntrack_netlink"))
  {
    cerr << "\n                      ***WARNING***\n"
     "Neither ip_conntrack_netlink nor nf_conntrack_netlink appears to be\n"
     "loaded. Unless one is compiled into your kernel, please load one and\n"
     "run l7-filter again.\n\n";
    sleep(5); // give time for the user to notice the above.
  }
}

int main(int argc, char **argv) 
{
  int rc, qnum;
  string conffilename;
  pthread_t connection_tracking_thread;
  pthread_t queue_tracking_thread;

  handle_cmdline(qnum, conffilename, argc, argv);

  check_requirements();

  signal(SIGINT, handle_sigint);

  l7_classify * l7_classifier = new l7_classify(conffilename);
  l7_connection_tracker = new l7_conntrack(l7_classifier);
  l7_queue_tracker = new l7_queue(l7_connection_tracker);

  //start up the connection tracking thread
  rc = pthread_create(&connection_tracking_thread, NULL,
	start_connection_tracking_thread, NULL);

  if(rc){
    cerr << "Error creating ct thread. pthread_create returned " << rc << endl;
    exit(1);
  }

  //start up the queue thread
  rc = pthread_create(&queue_tracking_thread, NULL, 
	start_queue_thread, (void *)(&qnum));

  if (rc){
    cerr << "Error creating queue thread. pthread_create returned " <<rc <<endl;
    exit(1);
  }

  pthread_join(connection_tracking_thread, NULL);
  pthread_join(queue_tracking_thread, NULL);
}
