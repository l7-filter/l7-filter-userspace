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
#include "l7-queue.h"
#include "util.h"

l7_classify* l7_classifier;
unsigned int buflen; // Shouldn't really be global, but it's SO much easier

l7_connection::l7_connection() 
{
  pthread_mutex_init(&num_packets_mutex, NULL);
  pthread_mutex_init(&buffer_mutex, NULL);
  buffer = (char *)malloc(buflen+1);
  lengthsofar = 0;
  num_packets = 0;
  mark = 0;
}

l7_connection::~l7_connection() 
{
  //clean up stuff
  if(buffer) 
  {
    print_give_up(key, (unsigned char *)buffer, lengthsofar);
    free(buffer);
  }
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
  if (mark == 0 || mark == NO_MATCH_YET)
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
  pthread_mutex_lock(&buffer_mutex);

  int length = 0;
  int oldlength = lengthsofar;

  /* Strip nulls.  Add it to the end of the current data. */
  for(int i = 0; i < buflen-lengthsofar && i < appdatalen; i++) {
    if(app_data[i] != '\0') {
      buffer[length+oldlength] = app_data[i];
      length++;
    }
  }

  buffer[length+oldlength] = '\0';
  lengthsofar += length;
  l7printf(3, "Appended data. Length so far = %d\n", lengthsofar);

  pthread_mutex_unlock (&buffer_mutex);
}


char *l7_connection::get_buffer() 
{
  return (char *)buffer;
}

static int sprintf_conntrack_key(char *buf, struct nfct_conntrack *ct, 
                          unsigned int flags) 
{
  int size = 0;

  size += nfct_sprintf_protocol(buf, ct);
  size += nfct_sprintf_address(buf+size, &ct->tuple[NFCT_DIR_ORIGINAL]);
  size += nfct_sprintf_proto(buf+size, &ct->tuple[NFCT_DIR_ORIGINAL]);

  /* Delete the last blank space */
  buf[size-1] = '\0';

  return size;
}

static string make_key(nfct_conntrack* ct, int flags)
{
  char key[512];
  int keysize = sprintf_conntrack_key(key, ct, flags);
  if(keysize >= 512){
    cerr << "Yike! Overflowed key!\n";
    exit(1);
  }
  l7printf(2, "Made key from ct:\t%s\n", key);
  return key;
}

static int l7_handle_conntrack_event(void *arg, unsigned int flags, int type, 
					void *data)
{
  l7_conntrack * l7_conntrack_handler = (l7_conntrack *) data;

  nfct_conntrack* ct = (nfct_conntrack*)arg;

  // I don't think there is any demand for ICMP. These are enough work for now.
  if(ct->tuple[0].protonum != IPPROTO_TCP && 
     ct->tuple[0].protonum != IPPROTO_UDP) return 0;

  if(type == NFCT_MSG_DESTROY) l7printf(3, "Got event: NFCT_MSG_DESTROY\n");
  if(type == NFCT_MSG_NEW)     l7printf(3, "Got event: NFCT_MSG_NEW\n");
  if(type == NFCT_MSG_UPDATE)  l7printf(3, "Got event: NFCT_MSG_UPDATE\n");
  if(type == NFCT_MSG_UNKNOWN) l7printf(3, "Got event: NFCT_MSG_UNKNOWN\n");

  // On the first packet, create the connection buffer, etc.
  if(type == NFCT_MSG_NEW){
    string key = make_key(ct, flags);
    if (l7_conntrack_handler->get_l7_connection(key)){
      // this happens sometimes
      cerr << "Received NFCT_MSG_NEW but already have a connection. Packets = " 
           << l7_conntrack_handler->get_l7_connection(key)->get_num_packets() 
           << endl;
      l7_conntrack_handler->remove_l7_connection(key);
    }
    
    l7_connection *thisconnection = new l7_connection();
    l7_conntrack_handler->add_l7_connection(thisconnection, key);
    thisconnection->key = key;
  }
  else if(type == NFCT_MSG_DESTROY){
    // clean up the connection buffer, etc.
    string key = make_key(ct, flags);
    if(l7_conntrack_handler->get_l7_connection(key)){
      l7_conntrack_handler->remove_l7_connection(key);
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
  int ret = 0, errors = 0;
  
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
  l7_connections[key] = connection;
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
  ret = nfct_event_conntrack(cth); // this is the main loop
  
  nfct_close(cth);
  nfct_conntrack_free(ct);
}
