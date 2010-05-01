/*
  The l7-queue class handles libnetfilter-queue events and passes 
  packets to their appropriate conntack for classification. 
  
  By Ethan Sommer <sommere@users.sf.net> and Matthew Strait 
  <quadong@users.sf.net>, Nov 2006.
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

#include "l7-conntrack.h"
#include "l7-queue.h"

extern "C" {
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
}


l7_queue::l7_queue(l7_conntrack *connection_tracker) 
{
  l7_connection_tracker = connection_tracker;
}


l7_queue::~l7_queue() 
{
}


void l7_queue::start() 
{
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int rv;
  char buf[4096];

  //cout << "opening library handle\n";
  h = nfq_open();
  if (!h) {
    cerr << "error during nfq_open()\n";
    exit(1);
  }

  //cout << "unbinding existing nf_queue handler for AF_INET (if any)\n";
  if (nfq_unbind_pf(h, AF_INET) < 0) {
    cerr << "error during nfq_unbind_pf()\n";
    exit(1);
  }

  //cout << "binding nfnetlink_queue as nf_queue handler for AF_INET\n";
  if (nfq_bind_pf(h, AF_INET) < 0) {
    cerr << "error during nfq_bind_pf()\n";
    exit(1);
  }

  //cout << "binding this socket to queue '0'\n";
  qh = nfq_create_queue(h,  0, &l7_queue_cb, this);
  if (!qh) {
    cerr << "error during nfq_create_queue()\n";
    exit(1);
  }

  //cout << "setting copy_packet mode\n";
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    cerr << "can't set packet_copy mode\n";
    exit(1);
  }

  nh = nfq_nfnlh(h);
  fd = nfnl_fd(nh);

  while (true) {
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
      nfq_handle_packet(h, buf, rv);
    
    cerr << "error recv returned negative value" << endl;
    cerr << "rv=" << rv << endl;
    cerr << "errno=" << errno << endl;
    cerr << "errstr=" << strerror(errno) << endl;
  }
  cout << "unbinding from queue 0\n";
  nfq_destroy_queue(qh);

  cout << "closing library handle\n";
  nfq_close(h);

  exit(0);
}

u_int32_t l7_queue::handle_packet(nfq_data * tb) 
{
  int id = 0, ret, dataoffset, datalen;
  u_int32_t mark, ifi; 
  struct nfqnl_msg_packet_hdr *ph;
  char * data;
  l7_connection * connection;

  ph = nfq_get_msg_packet_hdr(tb);
  if (ph){
    id = ntohl(ph->packet_id);
    #ifdef DEBUG
    printf("hw_protocol=0x%04x hook=%u id=%u ",ntohs(ph->hw_protocol),ph->hook,id);
    #endif
  }

  mark = nfq_get_nfmark(tb);
  #ifdef DEBUG
  if (mark) cout << "mark = " << mark << " ";
  #endif

  ifi = nfq_get_indev(tb);
  #ifdef DEBUG
  if (ifi) cout << "indev = " << ifi << " ";
  #endif 

  ifi = nfq_get_outdev(tb);
  #ifdef DEBUG
  if (ifi) cout << "outdev = " << ifi << " ";
  #endif

  ret = nfq_get_payload(tb, &data);
  #ifdef DEBUG
  if (ret >= 0) cout << "payload_len = " << ret << " ";
  #endif

  dataoffset = app_data_offset((const unsigned char*)data);
  datalen = ret - dataoffset;

  if(datalen > 0){
    //find the conntrack 
    string key = get_conntrack_key((const unsigned char*)data, false);
    connection = l7_connection_tracker->get_l7_connection(key);

    //if(connection) cout << "Found connection orig:\t" << key << endl;    
    if(!connection){
      //find the conntrack 
      string key = get_conntrack_key((const unsigned char*)data, true);
      connection = l7_connection_tracker->get_l7_connection(key);

      //if(connection) cout << "Found connection reply:\t" << key << endl;

      // It seems to routinely not get the UDP conntrack until the 2nd or 3rd
      // packet.  Tested with DNS.
      if(!connection) cout << "Got packet but had no connection:\t" << key << endl;
    }
    
    if(connection){
      connection->increment_num_packets();
      if(connection->get_mark() != 0)
	mark = connection->get_mark();
      
      else if(connection->get_num_packets() <= L7_NUM_PACKETS){
        connection->append_to_buffer((char*)(data+dataoffset),ret-dataoffset); 
        mark = connection->classify();
        if(mark == 0) mark = NO_MATCH_YET; // Nothing matched
      }
      else{
        mark = NO_MATCH; // Nothing matched before and we've given up
        if(connection->get_num_packets() == L7_NUM_PACKETS+1){
          cerr << "Gave up on " << key << endl << "Data was: " 
               << friendly_print((unsigned char *)connection->buffer, connection->lengthsofar)
               << endl;
        }
      }
    }
  }
  else mark = NO_MATCH_YET; // no application data

  #ifdef DEBUG
  putchar('\n');
  #endif

  if(mark == 0){
    #ifdef DEBUG
    cerr << "mark was still 0" << endl;
    #endif
    mark = NO_MATCH_YET;
  }
  
  return mark;
}


// Returns a string that uniquely defines the connection
string l7_queue::get_conntrack_key(const unsigned char *data, bool reverse) 
{
  char * buf = (char *)malloc(256);
  int i;
  int ip_hl = 4*(data[0] & 0x0f);
  char ip_protocol = data[9];

  if(ip_protocol == IPPROTO_TCP){
    if(reverse){
      snprintf(buf, 255, "tcp      6 src=%d.%d.%d.%d dst=%d.%d.%d.%d sport=%d dport=%d",
	      data[12], data[13], data[14], data[15],
	      data[16], data[17], data[18], data[19],
	      (data[ip_hl]*256+data[ip_hl+1]),(data[ip_hl+2]*256+data[ip_hl+3]));
    }
    else{
      snprintf(buf, 255, "tcp      6 src=%d.%d.%d.%d dst=%d.%d.%d.%d sport=%d dport=%d",
	      data[16], data[17], data[18], data[19],
	      data[12], data[13], data[14], data[15],
	      (data[ip_hl+2]*256+data[ip_hl+3]),(data[ip_hl]*256+data[ip_hl+1]));
    }
  }
  else if(ip_protocol == IPPROTO_UDP){
    if(reverse){
      snprintf(buf, 255, "udp      17 src=%d.%d.%d.%d dst=%d.%d.%d.%d sport=%d dport=%d",
	      data[12], data[13], data[14], data[15],
	      data[16], data[17], data[18], data[19],
	      (data[ip_hl]*256+data[ip_hl+1]),(data[ip_hl+2]*256+data[ip_hl+3]));
    }
    else{
      snprintf(buf, 255, "udp      17 src=%d.%d.%d.%d dst=%d.%d.%d.%d sport=%d dport=%d",
	      data[16], data[17], data[18], data[19],
	      data[12], data[13], data[14], data[15],
	      (data[ip_hl+2]*256+data[ip_hl+3]),(data[ip_hl]*256+data[ip_hl+1]));
    }
  }
  else{
    cout << "Tried to handle unsupported protocol!\n";
    buf[0] = '\0';
  }
  string answer = buf;
  free(buf);

  //cout << "Made key:\t" << answer << endl;

  return answer;
}

/* Returns offset the into the skb->data that the application data starts */
int l7_queue::app_data_offset(const unsigned char *data)
{
  int i;
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
      cout << "Tried to handle unsupported protocol!\n";
      return ip_hl + 8; /* something reasonable */
  }
}

// Returns the data with non-printable characters replaced with dots.
// If the input length is zero, returns NULL
string l7_queue::friendly_print(unsigned char * s, int size)
{
  char * f = (char *)malloc(size + 1);
  
  int i;
  if (size <= 0) return NULL;

  if(!f){
    cerr << "Out of memory in friendly_print, bailing.\n";
    return NULL;
  }
  for(i = 0; i < size; i++){
    if(isprint(s[i]) && s[i] < 128)     f[i] = s[i];
    else if(isspace(s[i]))              f[i] = ' ';
    else                                f[i] = '.';
  }
  f[i] = '\0';

  string answer = f;
  free(f);
  return answer;
}

static int l7_queue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		       struct nfq_data *nfa, void *data) 
{
  struct nfqnl_msg_packet_hdr *ph;

  u_int32_t id=0;
  ph = nfq_get_msg_packet_hdr(nfa);
  if (ph){
    id = ntohl(ph->packet_id);
  }
  u_int32_t mark = nfq_get_nfmark(nfa);
  #ifdef DEBUG
  cerr << "preMark=" << mark << endl; 
  #endif

  if (mark!=0) 
    return nfq_set_verdict_mark(qh, id, NF_ACCEPT,htonl(mark), 0, NULL);

  mark = ((l7_queue *)data)->handle_packet(nfa);
  
  return nfq_set_verdict_mark(qh, id, NF_REPEAT,htonl(mark), 0, NULL);
}
