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
*/

using namespace std;

#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <map>

extern "C" {
#include <linux/netfilter.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
}

#include "l7-conntrack.h"
#include "l7-classify.h"

l7_classify* l7_classifier;

l7_connection::l7_connection(string key) 
{
  this->key=key;
  pthread_mutex_init(&num_packets_mutex, NULL);
  pthread_mutex_init(&buffer_mutex, NULL);
  lengthsofar=0;
  num_packets=0;
  mark=0;
}

l7_connection::~l7_connection () 
{
  //clean up stuff
  pthread_mutex_destroy(&num_packets_mutex);
  pthread_mutex_destroy(&buffer_mutex);
}

void l7_connection::increment_num_packets() 
{
  pthread_mutex_lock (&num_packets_mutex);
  num_packets++;
  pthread_mutex_unlock (&num_packets_mutex);
}

int l7_connection::get_num_packets() 
{
  /* num_packets _might_ be modified in a different thread, 
     but it isn't critical if we are off by a few, and num_packets 
     might be modified between when this returns and is used anyway
     so if it were critical we should put the locks around the whole 
     critical section */
  return num_packets;
}

// Returns old mark if the connection is classified already.  
// Otherwise, attempts to classify it.
u_int32_t l7_connection::classify() 
{
  pthread_mutex_lock (&buffer_mutex);
  if (mark == 0)
    mark = l7_classifier->classify(buffer);

  pthread_mutex_unlock (&buffer_mutex);
  return mark;
}

u_int32_t l7_connection::get_mark() 
{
  return mark;
}

void l7_connection::append_to_buffer(char *app_data, int appdatalen) 
{
  pthread_mutex_lock (&buffer_mutex);

  int length = 0, i;
  int oldlength = lengthsofar;

  /* Strip nulls. Make everything lower case (TODO: make this more 
     flexible).  Add it to the end of the current data. */
  for(i = 0; i < maxdatalen-lengthsofar-1 && i < appdatalen; i++) {
    if(app_data[i] != '\0') {
      buffer[length+oldlength] =
	/* the kernel version of tolower mungs 'upper ascii' */
	isascii(app_data[i])? tolower(app_data[i]) : app_data[i];
      length++;
    }
  }

  buffer[length+oldlength] = '\0';
  lengthsofar = length + lengthsofar;
  //cerr << "length so far: " << lengthsofar << endl;

  pthread_mutex_unlock (&buffer_mutex);
}


char *l7_connection::get_buffer() 
{
  return (char *)buffer;
}

// XXX NOT consistent with get_conntrack_key!  Nothing will work until this is fixed!
static int sprintf_conntrack_key(char *buf, struct nfct_conntrack *ct, 
                          unsigned int flags) 
{
  int size = 0;

  size += nfct_sprintf_protocol(buf, ct);
  size += nfct_sprintf_address(buf+size, &ct->tuple[NFCT_DIR_ORIGINAL]);
  size += nfct_sprintf_proto(buf+size, &ct->tuple[NFCT_DIR_ORIGINAL]);

  /* Delete the last blank space */
  return size - 1;
}


static int l7_handle_conntrack_event(void *arg, unsigned int flags, int type, 
					void *data)
{
  l7_conntrack * l7_conntrack_handler = (l7_conntrack *) data;
  static int counter = 0, size, keysize = 0;

  char key[512];
  char buf[512];

  nfct_conntrack* ct = (nfct_conntrack*)arg;

  // I don't think there is any demand for ICMP.  These two are enough work for now.
  if(ct->tuple[0].protonum != IPPROTO_TCP && ct->tuple[0].protonum != IPPROTO_UDP) return 0;

  keysize = sprintf_conntrack_key(key, (nfct_conntrack*)arg, flags);
  if(keysize >= 512){ cerr << "Yike!\n"; exit(1); } // catch overflow.
  sprintf(key+keysize, "");
  string skey = key;

  #ifdef DEBUG  
  if(type == NFCT_MSG_DESTROY) cout << "NFCT_MSG_DESTROY\t";
  if(type == NFCT_MSG_NEW) cout << "NFCT_MSG_NEW\t";
  if(type == NFCT_MSG_UPDATE) cout << "NFCT_MSG_UPDATE\t";
  if(type == NFCT_MSG_UNKNOWN) cout << "NFCT_MSG_UNKNOWN\t";
  cout << key << endl;
  #endif

  if (type == NFCT_MSG_NEW){ // first packet
    // create the connection buffer, etc.
    if (l7_conntrack_handler->get_l7_connection(skey)){
      cerr << "Received NFCT_MSG_NEW but we already have a connection" << endl;
      cerr << "Num packets = " << l7_conntrack_handler->get_l7_connection(skey)->get_num_packets() << endl;
      l7_conntrack_handler->remove_l7_connection(skey);
    } 
	  
    l7_connection *thisconnection = new l7_connection("foo");
    l7_conntrack_handler->add_l7_connection(thisconnection, skey);
    thisconnection->key=skey;
  }
  else if (type == NFCT_MSG_DESTROY){
    // clean up the connection buffer, etc
    if (l7_conntrack_handler->get_l7_connection(skey)){
      l7_conntrack_handler->remove_l7_connection(skey);
    }
  }
	
  return 0;
}


l7_conntrack::~l7_conntrack() 
{
  nfct_conntrack_free(ct);
  nfct_close(cth);
}

l7_conntrack::l7_conntrack(void* l7_classifier_in) 
{
  l7_classifier = (l7_classify *)l7_classifier_in;
  // Conntrack stuff
  unsigned long status = IPS_ASSURED | IPS_CONFIRMED;
  unsigned long timeout = 100;
  unsigned long mark = 0;
  unsigned long id = NFCT_ANY_ID;
  int ret = 0, errors = 0;
  
  // netfilter queue stuff
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int rv;
  char buf[4096];
  
  // Now open a handler that is subscribed to all possible events
  cth = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
  if (!cth) {
    cerr << "Can't open handler\n";
    errors++;
    ret = -ENOENT;
    nfct_conntrack_free(ct);
    exit(1);
  } 
}

l7_connection *l7_conntrack::get_l7_connection(const string key) 
{
  return l7_connections[key];
}

void l7_conntrack::add_l7_connection(l7_connection* connection, 
					const string key) 
{
  l7_connections[key]=connection;
}

void l7_conntrack::remove_l7_connection(const string key) 
{
  delete l7_connections[key];
  l7_connections.erase(l7_connections.find(key));
}

void l7_conntrack::start() 
{
  int ret;

  nfct_register_callback(cth, l7_handle_conntrack_event, (void *)this);
  ret = nfct_event_conntrack(cth);
  
  nfct_close(cth);
  nfct_conntrack_free(ct);
}
