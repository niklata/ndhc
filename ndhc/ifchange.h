/* ifchange.h - functions to call the interface change daemon
 * Time-stamp: <2011-03-31 03:44:18 nk>
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

#ifndef IFCHANGE_H_
#define IFCHANGE_H_

#include "packet.h"

enum {
    IFCHANGE_DECONFIG = 0,
    IFCHANGE_BOUND = 1,
    IFCHANGE_RENEW = 2,
    IFCHANGE_NAK = 4
};

void ifchange(struct dhcpmsg *packet, int mode);

#endif
