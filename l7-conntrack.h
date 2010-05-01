/*
  Functions and classes which track the conntracks for l7-filter
  
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
*/

#ifndef L7_CONNTRACK_H
#define L7_CONNTRACK_H

#include "l7-classify.h"
#include <map>

class l7_connection {
 private:
  int num_packets;
  int mark;

  pthread_mutex_t num_packets_mutex;
  pthread_mutex_t buffer_mutex;

 public:
  char * buffer;
  int lengthsofar; // length of data in buffer, not counting terminating NULL
  string key;
  l7_connection();
  ~l7_connection();
  void increment_num_packets();
  int get_num_packets();
  
  void append_to_buffer(char *inbuf, int appdatalen);
  char *get_buffer();
  u_int32_t classify();
  u_int32_t get_mark();
};

typedef map <string, l7_connection *> l7_map;

class l7_conntrack {
 private:
  l7_map l7_connections;
  struct nfct_conntrack *ct;
  struct nfct_handle *cth; // the callback

 public:
  l7_conntrack(void * foo);
  ~l7_conntrack();
  void start();
  l7_connection* get_l7_connection(const string key);
  void add_l7_connection(l7_connection *connection, const string key);
  void remove_l7_connection(const string key);
};

#endif           
