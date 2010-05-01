/*
  The l7-queue class handles libnetfilter-queue events and passes 
  packets to their appropriate conntack for classification. 
  
  By Ethan Sommer <sommere@users.sf.net> and Matthew Strait 
  <quadong@users.sf.net>, 2006-2007
  http://l7-filter.sf.net 

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version
  2 of the License, or (at your option) any later version.
  http://www.gnu.org/licenses/gpl.txt

  Based on nfqnl_test.c from libnetfilter-queue 0.0.12

  If you get error messages about running out of buffer space, increase it 
  with something like:

  echo 524280 > /proc/sys/net/core/rmem_default
  echo 524280 > /proc/sys/net/core/rmem_max
  echo 524280 > /proc/sys/net/core/wmem_default
  echo 524280 > /proc/sys/net/core/wmem_max
*/

using namespace std;
#include <pthread.h>

#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <map>
#include <netinet/in.h>

#include <cstring>

#include "l7-conntrack.h"
#include "l7-queue.h"
#include "util.h"

// Probably shouldn't really be global, but it's SO much easier
int maxpackets = 10; // by default.
int clobbermark = 0;

extern unsigned int markmask;
extern unsigned int maskfirstbit;


extern "C" {
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
}


static int l7_queue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		       struct nfq_data *nfa, void *data) 
{
  struct nfqnl_msg_packet_hdr *ph;

  u_int32_t id = 0;
  ph = nfq_get_msg_packet_hdr(nfa);
  if(ph)
    id = ntohl(ph->packet_id);
  
  u_int32_t wholemark = nfq_get_nfmark(nfa);

  // If it already has a mark (and we don't want to clobber it), 
  // just pass it back with the same mark
  if((wholemark<<maskfirstbit)&markmask != UNTOUCHED && !clobbermark){
    static unsigned int naaltered = 0;
    naaltered++;
    if((naaltered^(naaltered-1)) == (2*naaltered-1)) // is it a power of 2?
      cerr << "My part of the mark has already been altered, ignoring these "
              "packets!\n(" << naaltered << " ignored so far.) "
              "Fix your rules or use l7-filter -c.\n";
    return nfq_set_verdict_mark(qh, id, NF_ACCEPT, htonl(wholemark), 0, NULL);
  }

  return ((l7_queue *)data)->handle_packet(nfa, qh);
}


l7_queue::l7_queue(l7_conntrack *connection_tracker) 
{
  l7_connection_tracker = connection_tracker;
}


l7_queue::~l7_queue() 
{
}


void l7_queue::start(int queuenum) 
{
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int rv;
  char buf[4096];

  l7printf(3, "opening library handle\n");
  h = nfq_open();
  if(!h) {
    cerr << "error during nfq_open()\n";
    exit(1);
  }

  l7printf(3, "unbinding existing nf_queue handler for AF_INET (if any)\n");

  /* As per Patrick McHardy's suggestion at 
     http://www.spinics.net/lists/netfilter/msg42063.html
     we, for now, ignore the return value of nfq_unbind_pf() */
  if(nfq_unbind_pf(h, AF_INET) < 0 && 0) {
    cerr << "error during nfq_unbind_pf()\n";
    exit(1);
  }

  l7printf(3, "binding nfnetlink_queue as nf_queue handler for AF_INET\n");
  if(nfq_bind_pf(h, AF_INET) < 0) {
    cerr << "error during nfq_bind_pf()\n";
    exit(1);
  }

  l7printf(3, "binding this socket to queue '0'\n");
  qh = nfq_create_queue(h, queuenum, &l7_queue_cb, this);
  if(!qh) {
    cerr << "error during nfq_create_queue()\n";
    exit(1);
  }

  l7printf(3, "setting copy_packet mode\n");
  if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    cerr << "can't set packet_copy mode\n";
    exit(1);
  }

  nh = nfq_nfnlh(h);
  fd = nfnl_fd(nh);

  // this is the main loop
  while (true){
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
      nfq_handle_packet(h, buf, rv);
    
    cerr << "Error: recv() returned negative value." << endl;
    cerr << "rv=" << rv << endl;
    cerr << "errno=" << errno << endl;
    cerr << "errstr=" << strerror(errno) << endl << endl;
  }
  l7printf(3, "unbinding from queue 0\n");
  nfq_destroy_queue(qh);

  l7printf(3, "closing library handle\n");
  nfq_close(h);

  exit(0);
}

u_int32_t l7_queue::handle_packet(nfq_data * tb, struct nfq_q_handle *qh) 
{
  int id = 0, ret, dataoffset, datalen;
  u_int32_t wholemark, mark, ifi; 
  struct nfqnl_msg_packet_hdr *ph;
  char * data;
  l7_connection * connection;

  ph = nfq_get_msg_packet_hdr(tb);
  if(ph){
    id = ntohl(ph->packet_id);
    l7printf(4, "hw_protocol = 0x%04x hook = %u id = %u ", 
      ntohs(ph->hw_protocol), ph->hook, id);
  }

  // Need to get the wholemark so that we can pass the unmasked part back
  // Except for the print statement and debugging, there's not really any
  // reason to pull out the masked part, because it's always modified without
  // looking at it...
  wholemark = (nfq_get_nfmark(tb));
  if(clobbermark){
     mark = UNTOUCHED;
     wholemark = wholemark&(~markmask); // zero out our part of the mark
  }
  else mark = ((wholemark&markmask) >> maskfirstbit);
  l7printf(4, "wholemark = %#08x ", wholemark);
  l7printf(4, "mark = %d ", mark);

  ifi = nfq_get_indev(tb);
  if(ifi) l7printf(4, "indev = %d ", ifi);

  ifi = nfq_get_outdev(tb);
  if(ifi) l7printf(4, "outdev = %d ", ifi);

  ret = nfq_get_payload(tb, &data);
  if(ret >= 0) l7printf(4, "payload_len = %d\n", ret);
  
  char ip_protocol = data[9];

  // Ignore anything that's not TCP or UDP
  if(ip_protocol != IPPROTO_TCP && ip_protocol != IPPROTO_UDP)
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  dataoffset = app_data_offset((const unsigned char*)data);
  datalen = ret - dataoffset;

  //find the conntrack 
  string key = get_conntrack_key((const unsigned char*)data, false);
  connection = l7_connection_tracker->get_l7_connection(key);
  
  if(connection)
    l7printf(3, "Found connection orig:\t%s\n", key.c_str());

  if(!connection){
    //find the conntrack (backwards)
    string key = get_conntrack_key((const unsigned char*)data, true);
    connection = l7_connection_tracker->get_l7_connection(key);
  
    if(connection)
      l7printf(3, "Found connection reply:\t%s\n", key.c_str());
  
    // It seems to routinely not get the UDP conntrack until the 2nd or 3rd
    // packet.  Tested with DNS.
    if(!connection)
      l7printf(2, "Got packet, had no ct:\t%s\n", key.c_str());
  }

  // mark = the mark we found on the packet
  // connection->get_mark() = the mark that we have made internally
  if(connection){
    connection->increment_num_packets();
  
    if(datalen <= 0){
      l7printf(3, "Connection with no new application data ignored.\n");
      mark = NO_MATCH_YET; // no application data
    }
    else{
      if(connection->get_mark() != NO_MATCH_YET && 
         connection->get_mark() != UNTOUCHED){
        // It is classified already.  Reapply existing mark.
        mark = connection->get_mark();
      }
      else if(connection->get_num_packets() <= maxpackets){
        // Do the heavy lifting.
        connection->append_to_buffer((char*)(data+dataoffset),ret-dataoffset); 
        l7printf(3, "Packet #%d, data is: %s\n", connection->get_num_packets(),
                 friendly_print((unsigned char *)connection->buffer,
                                connection->lengthsofar).c_str());
          
        mark = connection->classify();
        if(mark != NO_MATCH_YET){ // Got a match, no need to keep data
          free(connection->buffer);
          connection->buffer = NULL; // marks it not to be free'd again
        }
      }
      else{ // num_packets > maxpackets and hasn't been classified
        mark = NO_MATCH;
        // if this is the first packet after we've given up, clean up
        if(connection->get_num_packets() == maxpackets+1){
          print_give_up(key, (unsigned char *)connection->buffer, 
                        connection->lengthsofar);
        
          free(connection->buffer);
          connection->buffer = NULL; // marks it not to be free'd again
        } // endif should clean up
      } // endif whether should run match or what
    } // endif there is any new data
  } // endif we found the connection
  else{
    l7printf(3, "Didn't yet find\t%s\n", key.c_str());
    mark = NO_MATCH_YET;
  }

  if(mark == UNTOUCHED) cerr << "NOT REACHED. mark is still UNTOUCHED.\n";

  l7printf(4,"Set verdict ACCEPT, mark %#08x\n",(mark<<maskfirstbit)|wholemark);
  return nfq_set_verdict_mark(qh, id, NF_ACCEPT, 
                              htonl((mark<<maskfirstbit)|wholemark), 0, NULL);
}

// Returns a string that uniquely defines the connection
string l7_queue::get_conntrack_key(const unsigned char *data, bool reverse) 
{
  char * buf = (char *)malloc(256);
  int ip_hl = 4*(data[0] & 0x0f);
  char ip_protocol = data[9];

  if(ip_protocol == IPPROTO_TCP){
    if(reverse){
      snprintf(buf, 255, 
              "tcp      6 src=%d.%d.%d.%d dst=%d.%d.%d.%d sport=%d dport=%d",
	      data[12], data[13], data[14], data[15],
	      data[16], data[17], data[18], data[19],
	      data[ip_hl]*256+data[ip_hl+1], data[ip_hl+2]*256+data[ip_hl+3]);
    }
    else{
      snprintf(buf, 255, 
              "tcp      6 src=%d.%d.%d.%d dst=%d.%d.%d.%d sport=%d dport=%d",
	      data[16], data[17], data[18], data[19],
	      data[12], data[13], data[14], data[15],
	      data[ip_hl+2]*256+data[ip_hl+3], data[ip_hl]*256+data[ip_hl+1]);
    }
  }
  else if(ip_protocol == IPPROTO_UDP){
    if(reverse){
      snprintf(buf, 255, 
              "udp      17 src=%d.%d.%d.%d dst=%d.%d.%d.%d sport=%d dport=%d",
	      data[12], data[13], data[14], data[15],
	      data[16], data[17], data[18], data[19],
	      data[ip_hl]*256+data[ip_hl+1], data[ip_hl+2]*256+data[ip_hl+3]);
    }
    else{
      snprintf(buf, 255, 
              "udp      17 src=%d.%d.%d.%d dst=%d.%d.%d.%d sport=%d dport=%d",
	      data[16], data[17], data[18], data[19],
	      data[12], data[13], data[14], data[15],
	      data[ip_hl+2]*256+data[ip_hl+3], data[ip_hl]*256+data[ip_hl+1]);
    }
  }
  else{
    l7printf(0, "Tried to get conntrack key for unsupported protocol!\n");
    buf[0] = '\0';
  }
  string answer = buf;
  free(buf);

  l7printf(3, "Made key from packet:\t%s\n", answer.c_str());

  return answer;
}

/* Returns offset the into the skb->data that the application data starts */
int l7_queue::app_data_offset(const unsigned char *data)
{
  int ip_hl = 4*(data[0] & 0x0f);
  char ip_protocol = data[9];

  if(ip_protocol == IPPROTO_TCP){
    // 12 == offset into TCP header for the header length field.
    int tcp_hl = 4*(data[ip_hl + 12]>>4);
    return ip_hl + tcp_hl;
  }
  else if(ip_protocol == IPPROTO_UDP){
    return ip_hl + 8; /* UDP header is always 8 bytes */
  }
  else{
      l7printf(0, "Tried to get app data offset for unsupported protocol!\n");
      return ip_hl + 8; /* something reasonable */
  }
}
