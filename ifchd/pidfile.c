#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "defines.h"
#include "log.h"

void write_pid(char *file) {
    FILE *f;
    char buf[MAXLINE];

    if (!file)
	return;

    f = fopen(file, "w");
    if (f == NULL) {
	log_line("FATAL - failed to open pid file \"%s\"!\n", file);
	exit(EXIT_FAILURE);
    }

    snprintf(buf, sizeof buf, "%i", (unsigned int)getpid());
    fwrite(buf, sizeof (char), strlen(buf), f);

    if (fclose(f) != 0) {
	log_line("FATAL - failed to close pid file \"%s\"!\n", file);
	exit(EXIT_FAILURE);
    }
}

/* Return 0 on success, -1 on failure. */
int file_exists(char *file, char *mode) {
    FILE *f;

    if (file == NULL || mode == NULL)
	return -1;

    f = fopen(file, mode);
    if (f == NULL)
	return -1;
    fclose(f);
    return 0;
}

