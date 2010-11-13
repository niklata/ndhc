/*
 * options.c -- DHCP server option packet tools
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 * Fixes and hardening: Nicholas J. Kain <njkain at gmail dot com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "dhcpd.h"
#include "options.h"
#include "leases.h"

/* supported options are easily added here */
struct dhcp_option options[] = {
    /* name[10]     flags                                   code */
    {"subnet"   ,   OPTION_IP | OPTION_REQ,                 0x01},
    {"timezone" ,   OPTION_S32,                             0x02},
    {"router"   ,   OPTION_IP | OPTION_LIST | OPTION_REQ,   0x03},
    {"timesvr"  ,   OPTION_IP | OPTION_LIST,                0x04},
    {"namesvr"  ,   OPTION_IP | OPTION_LIST,                0x05},
    {"dns"      ,   OPTION_IP | OPTION_LIST | OPTION_REQ,   0x06},
    {"logsvr"   ,   OPTION_IP | OPTION_LIST,                0x07},
    {"cookiesvr",   OPTION_IP | OPTION_LIST,                0x08},
    {"lprsvr"   ,   OPTION_IP | OPTION_LIST,                0x09},
    {"hostname" ,   OPTION_STRING | OPTION_REQ,             0x0c},
    {"bootsize" ,   OPTION_U16,                             0x0d},
    {"domain"   ,   OPTION_STRING | OPTION_REQ,             0x0f},
    {"swapsvr"  ,   OPTION_IP,                              0x10},
    {"rootpath" ,   OPTION_STRING,                          0x11},
    {"ipttl"    ,   OPTION_U8,                              0x17},
    {"mtu"      ,   OPTION_U16,                             0x1a},
    {"broadcast",   OPTION_IP | OPTION_REQ,                 0x1c},
    {"ntpsrv"   ,   OPTION_IP | OPTION_LIST,                0x2a},
    {"wins"     ,   OPTION_IP | OPTION_LIST,                0x2c},
    {"requestip",   OPTION_IP,                              0x32},
    {"lease"    ,   OPTION_U32,                             0x33},
    {"dhcptype" ,   OPTION_U8,                              0x35},
    {"serverid" ,   OPTION_IP,                              0x36},
    {"message"  ,   OPTION_STRING,                          0x38},
    {"tftp"     ,   OPTION_STRING,                          0x42},
    {"bootfile" ,   OPTION_STRING,                          0x43},
    {""         ,   0x00,                                   0x00}
};

/* Lengths of the different option types */
int option_lengths[] = {
	[OPTION_IP] =       4,
	[OPTION_IP_PAIR] =  8,
	[OPTION_BOOLEAN] =  1,
	[OPTION_STRING] =   1,
	[OPTION_U8] =       1,
	[OPTION_U16] =      2,
	[OPTION_S16] =      2,
	[OPTION_U32] =      4,
	[OPTION_S32] =      4
};


/* get an option with bounds checking (warning, not aligned). */
unsigned char *get_option(struct dhcpMessage *packet, int code)
{
	int i = 0, length = 308;
	unsigned char *optionptr;
	int over = 0, done = 0, curr = OPTION_FIELD;

	optionptr = packet->options;
	while (!done) {
		if (i >= length) {
			log_warning("bogus packet, option fields too long.");
			return NULL;
		}
		if (optionptr[i + OPT_CODE] == code) {
			if (i + 1 + optionptr[i + OPT_LEN] >= length) {
				log_warning("bogus packet, option fields too long.");
				return NULL;
			}
			return optionptr + i + 2;
		}
		switch (optionptr[i + OPT_CODE]) {
			case DHCP_PADDING:
				i++;
				break;
			case DHCP_OPTION_OVER:
				if (i + 1 + optionptr[i + OPT_LEN] >= length) {
					log_warning("bogus packet, option fields too long.");
					return NULL;
				}
				over = optionptr[i + 3];
				i += optionptr[OPT_LEN] + 2;
				break;
			case DHCP_END:
				if (curr == OPTION_FIELD && over & FILE_FIELD) {
					optionptr = packet->file;
					i = 0;
					length = 128;
					curr = FILE_FIELD;
				} else if (curr == FILE_FIELD && over & SNAME_FIELD) {
					optionptr = packet->sname;
					i = 0;
					length = 64;
					curr = SNAME_FIELD;
				} else done = 1;
				break;
			default:
				i += optionptr[OPT_LEN + i] + 2;
		}
	}
	return NULL;
}


/* return the position of the 'end' option */
int end_option(unsigned char *optionptr)
{
	int i = 0;

	while (i < 308 && optionptr[i] != DHCP_END) {
		if (optionptr[i] == DHCP_PADDING)
			++i;
		else
			i += optionptr[i + OPT_LEN] + 2;
	}
	return (i < 308 ? i : 308);
}


/* add an option string to the options (an option string contains an option
 * code, length, then data) */
int add_option_string(unsigned char *optionptr, unsigned char *string)
{
	int end = end_option(optionptr);

	/* end position + string length + option code/length + end option */
	if (end + string[OPT_LEN] + 2 + 1 >= 308) {
		log_error("Option 0x%02x did not fit into the packet!",
				  string[OPT_CODE]);
		return 0;
	}
	log_line("adding option 0x%02x", string[OPT_CODE]);
	memcpy(optionptr + end, string, string[OPT_LEN] + 2);
	optionptr[end + string[OPT_LEN] + 2] = DHCP_END;
	return string[OPT_LEN] + 2;
}

int add_simple_option(unsigned char *optionptr, unsigned char code,
					  uint32_t data)
{
	int i, length = 0;
	unsigned char option[2 + 4];

	for (i = 0; options[i].code; i++)
		if (options[i].code == code) {
			length = option_lengths[options[i].flags & TYPE_MASK];
		}

	option[OPT_CODE] = code;
	option[OPT_LEN] = (unsigned char)length;

	if (!length) {
		log_error("Could not add option 0x%02x", code);
		return 0;
	} else if (length == 1) {
		uint8_t t = (uint8_t)data;
		memcpy(option + 2, &t, 1);
	} else if (length == 2) {
		uint16_t t = (uint16_t)data;
		memcpy(option + 2, &t, 2);
	} else if (length == 4) {
		uint32_t t = (uint32_t)data;
		memcpy(option + 2, &t, 4);
	}
	return add_option_string(optionptr, option);
}

/* find option 'code' in opt_list */
struct option_set *find_option(struct option_set *opt_list, char code)
{
	while (opt_list && opt_list->data[OPT_CODE] < code)
		opt_list = opt_list->next;

	if (opt_list && opt_list->data[OPT_CODE] == code) return opt_list;
	else return NULL;
}
