
//
// (c) 2008-2009 devolo AG, Aachen (Germany)
//

#include <sys/time.h>

struct MSCounter 
{ 
  unsigned long operator()() 
  {
    struct timeval tv;
    gettimeofday(&tv, 0);
    unsigned long long val = 1000;
    val *= tv.tv_sec;
    val = (val + (tv.tv_usec / 1000));
    return (unsigned long)val;
  } 
};
