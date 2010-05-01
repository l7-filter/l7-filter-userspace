#include <string>

#ifndef L7_UTIL_H
#define L7_UTIL_H

void l7printf(int triviality, const char * format, ...);
string friendly_print(unsigned char * s, int size);
void print_give_up(string key, unsigned char * buf, int len);

#endif
