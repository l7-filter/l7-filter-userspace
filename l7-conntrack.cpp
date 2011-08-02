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
#include <cstring>

extern "C" {
#include <linux/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
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
  if(buffer){
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
  if(mark == NO_MATCH_YET || mark == UNTOUCHED)
    mark = l7_classifier->classify(buffer);
  else
    cerr << "NOT REACHED. should have taken care of this case already.\n";

  pthread_mutex_unlock (&buffer_mutex);
  return mark;
}

u_int32_t l7_connection::get_mark() 
{
  return mark;
}

void l7_connection::append_to_buffer(char *app_data, unsigned int appdatalen) 
{
  pthread_mutex_lock(&buffer_mutex);

  unsigned int length = 0, oldlength = lengthsofar;

  /* Strip nulls.  Add it to the end of the current data. */
  for(unsigned int i = 0; i < buflen-lengthsofar && i < appdatalen; i++) {
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

static string make_key4(u_int32_t a, u_int32_t b, u_int16_t s,
			u_int16_t d, u_int8_t p)
{
  char key[512];

  if (p != IPPROTO_TCP  && p != IPPROTO_UDP) {
	l7printf(0, "Tried to get conntrack key for unsupported protocol!\n");
	return "";
  }
  int keysize  = snprintf(key, sizeof(key), "%08x:%04x-%08x:%04x %02x", a, s, b, d, p);
  if(keysize >= 512){
    cerr << "Yike! Overflowed key!\n";
    exit(1);
  }
  return key;
}

static string make_key_from_ct(const nf_conntrack* ct)
{
	u_int32_t src4 = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
	u_int32_t dst4 = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
	u_int16_t srcport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
	u_int16_t dstport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
	u_int8_t l4proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);

	string key = make_key4(src4, dst4, srcport, dstport, l4proto);
	l7printf(2, "Made key from ct:\t%s\n", key.c_str());
	return key;
}

static int l7_handle_conntrack_event(const struct nlmsghdr *nlh,
					enum nf_conntrack_msg_type type,
					struct nf_conntrack *ct,
					void *data)
{
  l7_conntrack * l7_conntrack_handler = (l7_conntrack *) data;
  u_int8_t l4proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);

  // I don't think there is any demand for ICMP. These are enough work for now.
  if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP)
     return 0;

  std::string key;
  switch (type) {
  // On the first packet, create the connection buffer, etc.
  case NFCT_T_NEW: {
	l7printf(3, "Got event: NFCT_T_NEW\n");

	key = make_key_from_ct(ct);
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
  break;
  case NFCT_T_DESTROY:
	l7printf(3, "Got event: NFCT_T_DESTROY\n");
	// clean up the connection buffer, etc.
	key = make_key_from_ct(ct);
	if (l7_conntrack_handler->get_l7_connection(key))
		l7_conntrack_handler->remove_l7_connection(key);
	break;
  case NFCT_T_UPDATE:
	l7printf(3, "Got event: NFCT_T_UPDATE\n");
	break;
  /* FIXME: this MUST be handled properly: */
  case NFCT_T_ERROR:
	l7printf(3, "Got event: NFCT_T_ERROR\n");
	break;
  default:
	l7printf(1, "Got event type: 0x%x\n", type);
	break;
  }
 return 0;
}

// turn raw packet into a key string
string l7_conntrack::make_key(const unsigned char *packetdata, bool reverse) const
{
	u_int16_t sport, dport;
	unsigned int ihl;
	struct iphdr iph;
	string key;

	memcpy(&iph, packetdata, sizeof(iph));

	ihl = iph.ihl << 2;
	memcpy(&sport, packetdata + ihl, sizeof(sport));
	memcpy(&dport, packetdata + ihl + 2, sizeof(dport));

	if (reverse)
		key = make_key4(iph.daddr, iph.saddr,
				dport, sport, iph.protocol);
	else
		key = make_key4(iph.saddr, iph.daddr,
				 sport, dport, iph.protocol);

	l7printf(3, "Made key from packet:\t%s\n", key.c_str());
	return key;
}

l7_conntrack::~l7_conntrack() 
{
  nfct_close(cth);
  pthread_mutex_destroy(&map_mutex);
}

l7_conntrack::l7_conntrack(void* l7_classifier_in) 
{
  pthread_mutex_init(&map_mutex, NULL);
  l7_classifier = (l7_classify *)l7_classifier_in;
  
  // Now open a handler that is subscribed to all possible events
  cth = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
  if (!cth) {
    cerr<<"Can't open Netfilter connection tracking handler.  Are you root?\n";
    exit(1);
  } 
}

l7_connection *l7_conntrack::get_l7_connection(const string key) 
{
  l7_connection *conn;
  pthread_mutex_lock(&map_mutex);
  conn = l7_connections[key];
  pthread_mutex_unlock(&map_mutex);
  return conn;
}

void l7_conntrack::add_l7_connection(l7_connection* connection, 
					const string key) 
{
  pthread_mutex_lock(&map_mutex);
  l7_connections[key] = connection;
  pthread_mutex_unlock(&map_mutex);
}

void l7_conntrack::remove_l7_connection(const string key) 
{
  pthread_mutex_lock(&map_mutex);
  delete l7_connections[key];
  l7_connections.erase(l7_connections.find(key));
  pthread_mutex_unlock(&map_mutex);
}

void l7_conntrack::start() 
{
  int ret;

  nfct_callback_register2(cth, NFCT_T_ALL, l7_handle_conntrack_event, (void *)this);
  do {
	  ret = nfct_catch(cth);
  }  while (ret == 0);

  std::cerr <<  "nfct_catch returned " << ret << ", exiting" << std::endl;
  exit(ret);
}
