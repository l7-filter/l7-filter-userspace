/*

  Functions and classes which keep track of and use regexes to classify streams 
  of application data.
  
  By Ethan Sommer <sommere@users.sf.net> and Matthew Strait 
  <quadong@users.sf.net>, (C) Nov 2006-2007
  http://l7-filter.sf.net 

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version
  2 of the License, or (at your option) any later version.
  http://www.gnu.org/licenses/gpl.txt

*/


#ifndef L7_CLASSIFY_H
#define L7_CLASSIFY_H

using namespace std;
#include <string>
#include <list>
#include <sys/types.h>
#include <regex.h>
#include "l7-conntrack.h"


class l7_pattern {

 private:
  int mark;
  string pattern_string;
  int eflags; // for regexec
  int cflags; // for regcomp
  string name;
  regex_t preg;//the compiled regex
  char * pre_process(const char * s);
  int hex2dec(char c);

 public:
  l7_pattern(string name,string pattern_string,int eflags,int cflags,int mark);
  ~l7_pattern();
  bool matches(char * buffer);
  string getName();
  int getMark();
};

class l7_classify {

 private:
  int add_pattern_from_file(const string filename, int mark);
  list<l7_pattern *> patterns;
  
 public:
  l7_classify(string filename);
  ~l7_classify();
  int classify(char * buffer);
};


#endif          
