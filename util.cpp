using namespace std;

#include <stdio.h>
#include <stdarg.h>
#include <string>
#include <iostream>
#include "util.h"

// start with verbosity of 0. Each -v given on the cmd line increases this.
// -s sets it to -1.
int verbosity = 0;

void l7printf(int triviality, const char * format, ...)
{
        if(triviality <= verbosity){
	        va_list ap;
                va_start(ap, format);
                vprintf(format, ap);
                va_end(ap);
        }
}

// Returns the data with non-printable characters replaced with dots.
// If the input length is zero, returns NULL
string friendly_print(unsigned char * s, int size)
{
  string result = "";

  for(int i = 0; i < size; i++){
    if(isprint(s[i]) && s[i] < 128)     result += s[i];
    else if(isspace(s[i]))              result += ' ';
    else                                result += '.';
  }

  return result;
}

void print_give_up(string key, unsigned char * buf, int len)
{
  if(len > 1){
    l7printf(1, "Gave up: %s. ", key.c_str());
    l7printf(1, "Data was:\n%s\n", friendly_print(buf, len).c_str());
   }
   else{
    l7printf(2, "Gave up: %s. ", key.c_str());
    l7printf(2, "No data in connection.\n");
  }
}
