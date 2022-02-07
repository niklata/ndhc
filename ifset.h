// Copyright 2004-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NJK_IFSET_H_
#define NJK_IFSET_H_
int perform_carrier(void);
int perform_ifup(void);
int perform_ip_subnet_bcast(const char *str_ipaddr,
                            const char *str_subnet,
                            const char *str_bcast);
int perform_router(const char *str, size_t len);
int perform_mtu(const char *str, size_t len);
#endif

