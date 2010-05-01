/*
  Functions and classes which track the conntracks for l7-filter.
  
  By Ethan Sommer <sommere@users.sf.net> and Matthew Strait 
  <quadong@users.sf.net>, (C) Nov 2006
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

#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <map>

#include "l7-conntrack.h"
#include "l7-queue.h"
#include "l7-classify.h"

extern "C" {
#include <linux/netfilter.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
}

static l7_conntrack* l7_connection_tracker;
static l7_queue* l7_queue_tracker;
static l7_classify* l7_classifier;

static void handle_sigint(int s) {
  delete l7_connection_tracker;
  exit(0);
}


//queue functions

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

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) 
{
  u_int32_t id = print_pkt(nfa);
  printf("entering callback\n");
  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void *start_connection_tracking_thread(void *data) 
{
  l7_connection_tracker->start();
  pthread_exit(NULL);
}

void *start_queue_thread(void *data) 
{
  l7_queue_tracker->start();
  pthread_exit(NULL);
}

int main(int argc, char **argv) 
{
  int rc;
  pthread_t connection_tracking_thread;
  pthread_t queue_tracking_thread;

  signal(SIGINT, handle_sigint);

  if(argc != 2){
    cerr << "Usage: l7-filter configuration_file\n";
    exit(1);
  }

  l7_classify * l7_classifier = new l7_classify(argv[1]);
  l7_connection_tracker = new l7_conntrack(l7_classifier);
  l7_queue_tracker = new l7_queue(l7_connection_tracker);

  //start up the connection tracking thread
  rc=pthread_create(&connection_tracking_thread,NULL,start_connection_tracking_thread,NULL);
  if (rc){
    cerr << "Error creating ct thread. pthread_create returned " << rc << endl;
    exit(1);
  }

  //start up the queue thread
  rc = pthread_create(&queue_tracking_thread, NULL,start_queue_thread, NULL);
  if (rc){
    cerr << "Error creating queue thread. pthread_create returned " <<rc <<endl;
    exit(1);
  }

  pthread_exit(NULL);
}
