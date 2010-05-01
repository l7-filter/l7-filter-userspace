/*
  Functions and classes which keep track of and use regexes to classify streams
  of application data.
  
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
#include <fstream>

#include <vector>
#include <string>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>

#define MAX_SUBDIRS 128
#define MAX_FN_LEN 256

string l7dir = "/etc/l7-protocols";

#include "l7-classify.h"
#include "l7-queue.h"
#include "l7-parse-patterns.h"
#include "util.h"

l7_pattern::l7_pattern(string name, string pattern_string, int eflags, 
  int cflags, int mark)
{
  this->name = name;
  this->pattern_string = pattern_string;
  this->eflags = eflags;
  this->cflags = cflags;
  this->mark = mark;
  char *preprocessed = pre_process(pattern_string.c_str());
  
  int rc = regcomp(&preg, preprocessed, cflags);
  if (rc != 0){
    cerr << "error compiling " << name << " -- " << pattern_string << endl;
    exit(1);
  }
}


int l7_pattern::hex2dec(char c) 
{
  switch (c){
    case '0' ... '9':
      return c - '0';
    case 'a' ... 'f':
      return c - 'a' + 10;
    case 'A' ... 'F':
      return c - 'A' + 10;
    default:
      cerr << "Bad hex digit, " << c << ", in regular expression!" << endl;
      exit(1);
  }
}


char * l7_pattern::pre_process(const char * s) 
{
  char * result = (char *)malloc(strlen(s) + 1);
  int sindex = 0, rindex = 0;
  while( sindex < strlen(s) ) {
    if( sindex + 3 < strlen(s) && s[sindex] == '\\' && s[sindex+1] == 'x' && 
	isxdigit(s[sindex + 2]) && isxdigit(s[sindex + 3]) ){

      result[rindex] = hex2dec(s[sindex + 2])*16 + hex2dec(s[sindex + 3]);

      switch ( result[rindex] ) {
        case '$':
        case '(':
        case ')':
        case '*':
        case '+':
        case '.':
        case '?':
        case '[':
        case ']':
        case '^':
        case '|':
        case '{':
        case '}':
        case '\\':
          cerr << "Warning: regexp contains a regexp control character, "
               << result[rindex] << ", in hex (\\x" << s[sindex + 2] 
               << s[sindex+3] << ".\nI recommend that you write this as "
               << result[rindex] << " or \\" << result[rindex] 
               << " depending on what you meant.\n";
          break;
        case '\0':
          cerr << "Warning: null (\\x00) in layer7 regexp. "
               << "A null terminates the regexp string!\n";
	  break;
        default:
          break;
      }
      sindex += 3; /* 4 total */
    }
    else
      result[rindex] = s[sindex];

    sindex++; 
    rindex++;
  }
  result[rindex] = '\0';

  return result;
}


bool l7_pattern::matches(char *buffer) 
{  
  int rc = regexec(&preg, buffer, 0, NULL, eflags);

  if(rc == 0)	return true;
  else		return false;
}


string l7_pattern::getName() 
{
  return name;
}


int l7_pattern::getMark() 
{
  return mark;
}

static char ** readl7dir(string dirname)
{
  DIR * scratchdir;
  struct dirent ** namelist;
  char ** subdirs = (char **)malloc(MAX_SUBDIRS * sizeof(char *));

  int n, d = 1;
  subdirs[0] = "";

  n = scandir(dirname.c_str(), &namelist, 0, alphasort);

  if (n < 0){
      perror("scandir");
      cerr << "Couldn't open " << dirname << endl;
      exit(1);
  }
  else{
    while(n--){
      char fulldirname[MAX_FN_LEN];

      snprintf(fulldirname, MAX_FN_LEN, "%s/%s", dirname.c_str(), 
               namelist[n]->d_name);

      if((scratchdir = opendir(fulldirname)) != NULL)
      {
        closedir(scratchdir);

        if(!strcmp(namelist[n]->d_name, ".") || 
           !strcmp(namelist[n]->d_name, ".."))
          /* do nothing */ ;
        else{
          subdirs[d] = (char *)malloc(strlen(namelist[n]->d_name) + 1);
          strcpy(subdirs[d], namelist[n]->d_name);
          d++;
          if(d >= MAX_SUBDIRS - 1)
          {
            cerr << "Too many subdirectories, skipping the rest!\n";
            break;
          }
        }
      }
      free(namelist[n]);
    }
    free(namelist);
  }
  
  subdirs[d] = NULL;
  return subdirs;
}

static string findpatternfile(string protocol)
{
  char filename[MAX_FN_LEN];
  char ** subdirs;
  int n = 0;

  subdirs = readl7dir(l7dir);

  while(subdirs[n] != NULL){
    int c = snprintf(filename, MAX_FN_LEN, "%s/%s/%s.pat", l7dir.c_str(), 
                     subdirs[n], protocol.c_str());

    if(c > MAX_FN_LEN){
      cerr << "Filename beginning with " << filename << " is too long!\n";
      exit(1);
    }

    ifstream test(filename);

    /* read in the pattern from the file */
    if(test.is_open()){
      test.close();
      string answer = filename;
      return answer;
    }
    n++;
  }

  cerr << "Couldn't find a pattern definition file for " << protocol << endl;
  exit(1);
}

// Loads in the configuration file
l7_classify::l7_classify(string filename)
{
  string line;
  int nrules = 0;

  ifstream conf(filename.c_str());

  l7printf(2, "Attempting to read configuration from %s\n", filename.c_str());

  if(!conf.is_open()){
    cerr << "Could not read from " << filename << endl;
    exit(1);
  }

  while(getline(conf, line)){
    stringstream sline;
    string proto, patternfile;
    int mk;
    bool nothingbutspaces = true;

    // Lines starting with # are comments
    if(line[0] == '#') continue;

    // blank lines are ignored
    for(unsigned int i = 0; i < line.size(); i++)
      if(!isspace(line[i])) nothingbutspaces = false;
    if(nothingbutspaces) continue;  

    sline << line;
    if(!(sline >> proto) || !(sline >> mk)){
      cerr << "Ignoring line because it isn't in the format 'protocol mark':"
           << line << endl;
      continue;
    }

    if(mk < 1 || mk > 65534){
      cerr << "Ignoring line because the mark is not in the range 1-65534:"
           << line << endl;
      continue;
    }

    patternfile = findpatternfile(proto);
    if(add_pattern_from_file(patternfile, mk)){
      nrules++;
      l7printf(0, "Added: %s\tmark=%d\n", proto.c_str(), mk);
    }
  }

  if(nrules < 1){
    cerr << "No valid rules, exiting.\n";
    exit(1);
  }
}


l7_classify::~l7_classify() 
{

}

// Returns 1 on sucess, 0 on failure
int l7_classify::add_pattern_from_file(string filename, int mark) 
{
  int eflags, cflags;
  string pattern = "";

  l7printf(2, "Attempting to load pattern from %s\n", filename.c_str());

  if(!parse_pattern_file(cflags, eflags, pattern, filename)){
    cerr << "Failed to parse pattern file " << filename << endl;
    return 0;
  }

  l7printf(2, "pattern='%s'\n", pattern.c_str());
  l7printf(2, "eflags=%d cflags=%d\n", eflags, cflags);

  l7_pattern *l7p=new l7_pattern(basename(filename),pattern,eflags,cflags,mark);
  patterns.push_back(l7p);
  return 1;
}

int l7_classify::classify(char * buffer) 
{
  list<l7_pattern *>::iterator current = patterns.begin();
  while (current != patterns.end()) {
    l7printf(3, "checking against %s\n", (*current)->getName().c_str());

    if((*current)->matches(buffer)){
      l7printf(1, "matched %s\n", (*current)->getName().c_str());
      return (*current)->getMark();
    }
    current++;
  }

  l7printf(3, "No match yet\n");
  return NO_MATCH_YET;
}
