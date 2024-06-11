#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif

#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

//1 represents first is later; 0 is same time; -1 is second later->
int compare_time(struct tm* tm1, struct tm* tm2)
{
    //from year to month to time to date->->->
    
    //year
    if(tm1->tm_year > tm2->tm_year)
        return 1;
    else if(tm1->tm_year < tm2->tm_year)
        return -1;
    //year's date
    if(tm1->tm_yday > tm2->tm_yday)
        return 1;
    else if(tm1->tm_yday < tm2->tm_yday)
        return -1;
    //hour
    if(tm1->tm_hour > tm2->tm_hour)
        return 1;
    else if(tm1->tm_hour < tm2->tm_hour)
        return -1;
    //minute
    if(tm1->tm_min > tm2->tm_min)
        return 1;
    else if(tm1->tm_min < tm2->tm_min)
        return -1;
    //second
    if(tm1->tm_sec > tm2->tm_sec)
        return 1;
    else if(tm1->tm_sec < tm2->tm_sec)
        return -1;
    else
        return 0;
    
}
