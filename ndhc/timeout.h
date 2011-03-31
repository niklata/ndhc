/* timeout.h - callbacks to react to event timeouts
 * Time-stamp: <2011-03-30 23:42:25 nk>
 *
 * (c) 2004-2011 Nicholas J. Kain <njkain at gmail dot com>
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

#ifndef TIMEOUT_H_
#define TIMEOUT_H_

#include "config.h"
#include "sys.h"

void handle_timeout(struct client_state_t *cs);

#endif /* TIMEOUT_H_ */
