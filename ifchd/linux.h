/* linux.h - ifchd Linux-specific functions include
 * Time-stamp: <2010-11-12 14:31:33 njk>
 *
 * (C) 2004-2010 Nicholas J. Kain <njkain at gmail dot com>
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

#ifndef NJK_IFCHD_LINUX_H_
#define NJK_IFCHD_LINUX_H_
void clear_if_data(int idx);
void initialize_if_data(void);
void add_permitted_if(char *s);
int authorized_peer(int sk, pid_t pid, uid_t uid, gid_t gid);
void perform_interface(int idx, char *str);
void perform_ip(int idx, char *str);
void perform_subnet(int idx, char *str);
void perform_router(int idx, char *str);
void perform_mtu(int idx, char *str);
void perform_broadcast(int idx, char *str);
#endif

