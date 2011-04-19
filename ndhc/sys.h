/* sys.h - linux-specific signal and epoll functions
 * Time-stamp: <2011-03-30 23:41:04 nk>
 *
 * (c) 2010-2011 Nicholas J. Kain <njkain at gmail dot com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef SYS_H_
#define SYS_H_

#include <sys/time.h>
#include "ndhc-defines.h"
#include "config.h"

static inline unsigned long long curms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
}

extern char pidfile[MAX_PATH_LENGTH];

void setup_signals(struct client_state_t *cs);
void background(struct client_state_t *cs);
void epoll_add(struct client_state_t *cs, int fd);
void epoll_del(struct client_state_t *cs, int fd);

#endif /* SYS_H_ */
