// Copyright 2022 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#ifndef NDHC_SCRIPTD_H_
#define NDHC_SCRIPTD_H_

#include <stdbool.h>

extern bool valid_script_file;

void request_scriptd_run(void);
void scriptd_main(void);

#endif

