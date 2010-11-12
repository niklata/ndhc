/* log.c - simple logging support for ncron
   (C) 2003 Nicholas J. Kain <njk@aerifal.cx>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */

#include <stdio.h>
#include <strings.h>
#include <syslog.h>
#include <stdarg.h>
#include "defines.h"

/* global logging flags */
int gflags_quiet = 0;
int gflags_detach = 1;

void log_line(char *format, ...) {
    va_list argp;

    if (format == NULL || gflags_quiet)
	return;

    if (gflags_detach) {
	openlog("ifchd", LOG_PID, LOG_DAEMON);
	va_start(argp, format);
	vsyslog(LOG_ERR | LOG_DAEMON, format, argp);
	va_end(argp);
	closelog();
    } else {
	va_start(argp, format);
	vfprintf(stderr, format, argp);
	va_end(argp);
    }
    closelog();
}
