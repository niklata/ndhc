/* netlink.h - netlink physical link notification handling and info retrieval
 *
 * (c) 2011 Nicholas J. Kain <njkain at gmail dot com>
 * (c) 2006-2007 Stefan Rompf <sux@loplof.de>
 *
 * This code was largely taken from Stefan Rompf's dhcpclient.
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

#ifndef NK_NETLINK_H_
#define NK_NETLINK_H_

#include "state.h"

int nl_open(struct client_state_t *cs);
void nl_close(struct client_state_t *cs);
void nl_queryifstatus(int ifidx, struct client_state_t *cs);
void handle_nl_message(struct client_state_t *cs);
int nl_getifdata(const char *ifname, struct client_state_t *cs);

#endif /* NK_NETLINK_H_ */
