#include <stdio.h>
#include <strings.h>
#include <stdarg.h>
#include <syslog.h>

void log_line(int level, char *format, ...) {
	va_list argp;

	if (format == NULL) return;

		va_start(argp, format);
		vfprintf(stderr, format, argp);
		va_end(argp);
		openlog("ndhc", 0, 0);
		va_start(argp, format);
		vsyslog(level, format, argp);
		va_end(argp);
		closelog();
}

