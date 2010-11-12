#ifndef H_LOG_H__
#define H_LOG_H__
#include <syslog.h>
void log_line(int level, char *format, ...); 
#ifdef DEBUG
#define debug log_line
#else
#define debug(...) 
#endif
#endif

