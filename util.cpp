#include <stdio.h>
#include <stdarg.h>
#include "util.h"

// start with verbosity level of 0. Each -v given on the cmd line increases this.
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
