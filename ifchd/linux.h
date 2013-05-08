/* linux.h - ifchd Linux-specific functions include
 *
 * Copyright (c) 2004-2012 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef NJK_IFCHD_LINUX_H_
#define NJK_IFCHD_LINUX_H_
void clear_if_data(struct ifchd_client *cl);
void initialize_if_data(void);
void add_permitted_if(char *s);
int authorized_peer(int sk, pid_t pid, uid_t uid, gid_t gid);
void perform_interface(struct ifchd_client *cl, const char *str, size_t len);
void perform_ip(struct ifchd_client *cl, const char *str, size_t len);
void perform_subnet(struct ifchd_client *cl, const char *str, size_t len);
void perform_router(struct ifchd_client *cl, const char *str, size_t len);
void perform_mtu(struct ifchd_client *cl, const char *str, size_t len);
void perform_broadcast(struct ifchd_client *cl, const char *str, size_t len);
#endif

