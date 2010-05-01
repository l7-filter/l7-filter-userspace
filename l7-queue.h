/*
  The l7-queue class handles libnetfilter-queue events and passes 
  packets to their appropriate conntack for classification. 
  
  By Ethan Sommer <sommere@users.sf.net> and Matthew Strait 
  <quadong@users.sf.net>, (C) 2006
  http://l7-filter.sf.net 

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version
  2 of the License, or (at your option) any later version.
  http://www.gnu.org/licenses/gpl.txt

  Based on nfqnl_test.c from  libnetfilter-queue 0.0.12
*/

#ifndef L7_QUEUE_H
#define L7_QUEUE_H

#include "l7-conntrack.h"


#define L7_NUM_PACKETS 8
#define NO_MATCH 65536
#define NO_MATCH_YET NO_MATCH-1

class l7_queue {
 private:
  l7_conntrack* l7_connection_tracker;
  string friendly_print(unsigned char * s,int size);
  int app_data_offset(const unsigned char *data);
  string get_conntrack_key(const unsigned char *data, bool reverse);

 public:
  l7_queue(l7_conntrack* connection_tracker);
  ~l7_queue();
  void start();
  u_int32_t handle_packet(struct nfq_data *nfa);
};

static int l7_queue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		       struct nfq_data *nfa, void *data);

#endif
