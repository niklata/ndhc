/* signals.c - abstracts signal handling
   (C) 2004 Nicholas J. Kain <njk@aerifal.cx>

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

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include "log.h"

void hook_signal(int signum, void (*fn)(int), int flags) {
    struct sigaction new_action;

    new_action.sa_handler = fn;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = flags;

    if (sigaction(signum, &new_action, NULL)) {
	log_line("FATAL - failed to hook signal %i\n", signum);
	exit(EXIT_FAILURE);
    }
}

void disable_signal(int signum) {
    struct sigaction new_action;

    new_action.sa_handler = SIG_IGN;
    sigemptyset(&new_action.sa_mask);

    if (sigaction(signum, &new_action, NULL)) {
	log_line("FATAL - failed to ignore signal %i\n", signum);
	exit(EXIT_FAILURE);
    }
}
