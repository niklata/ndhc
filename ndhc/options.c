/*
 * options.c -- DHCP server option packet tools
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 * Fixes and hardening: Nicholas J. Kain <njkain at gmail dot com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "options.h"

#include "log.h"
#include "malloc.h"

enum {
    OPT_CODE = 0,
    OPT_LEN  = 1,
    OPT_DATA = 2
};

/* supported options are easily added here */
struct dhcp_option options[] = {
    /* name[10]     type                                    code */
    {"subnet"   ,   OPTION_IP,                              0x01},
    {"timezone" ,   OPTION_S32,                             0x02},
    {"router"   ,   OPTION_IP,                              0x03},
    {"timesvr"  ,   OPTION_IP,                              0x04},
    {"namesvr"  ,   OPTION_IP,                              0x05},
    {"dns"      ,   OPTION_IP,                              0x06},
    {"logsvr"   ,   OPTION_IP,                              0x07},
    {"cookiesvr",   OPTION_IP,                              0x08},
    {"lprsvr"   ,   OPTION_IP,                              0x09},
    {"hostname" ,   OPTION_STRING,                          0x0c},
    {"bootsize" ,   OPTION_U16,                             0x0d},
    {"domain"   ,   OPTION_STRING,                          0x0f},
    {"swapsvr"  ,   OPTION_IP,                              0x10},
    {"rootpath" ,   OPTION_STRING,                          0x11},
    {"ipttl"    ,   OPTION_U8,                              0x17},
    {"mtu"      ,   OPTION_U16,                             0x1a},
    {"broadcast",   OPTION_IP,                              0x1c},
    {"ntpsrv"   ,   OPTION_IP,                              0x2a},
    {"wins"     ,   OPTION_IP,                              0x2c},
    {"requestip",   OPTION_IP,                              0x32},
    {"lease"    ,   OPTION_U32,                             0x33},
    {"dhcptype" ,   OPTION_U8,                              0x35},
    {"serverid" ,   OPTION_IP,                              0x36},
    {"message"  ,   OPTION_STRING,                          0x38},
    {"maxsize"  ,   OPTION_U16,                             0x39},
    {"tftp"     ,   OPTION_STRING,                          0x42},
    {"bootfile" ,   OPTION_STRING,                          0x43},
    {""         ,   OPTION_NONE,                            0x00}
};

// List of options that will be sent on the parameter request list to the
// remote DHCP server.
static unsigned char req_opts[] = {
	DHCP_SUBNET,
	DHCP_ROUTER,
	DHCP_DNS_SERVER,
	DHCP_HOST_NAME,
	DHCP_DOMAIN_NAME,
	DHCP_BROADCAST,
	0x00
};

static unsigned char list_opts[] = {
	DHCP_ROUTER,
	DHCP_TIME_SERVER,
	DHCP_NAME_SERVER,
	DHCP_DNS_SERVER,
	DHCP_LOG_SERVER,
	DHCP_COOKIE_SERVER,
	DHCP_LPR_SERVER,
	DHCP_NTP_SERVER,
	DHCP_WINS_SERVER,
	0x00
};

uint8_t option_length(enum option_type type)
{
	switch (type) {
		case OPTION_IP: return 4;
		case OPTION_U8: return 1;
		case OPTION_U16: return 2;
		case OPTION_S16: return 2;
		case OPTION_U32: return 4;
		case OPTION_S32: return 4;
		default: return 0;
	}
}

int option_valid_list(uint8_t code)
{
	int i;
	for (i = 0; i < sizeof list_opts; ++i)
		if (list_opts[i] == code)
			return 1;
	return 0;
}

size_t sizeof_option(unsigned char code, size_t datalen)
{
	if (code == DHCP_PADDING || code == DHCP_END)
		return 1;
	return 2 + datalen;
}

// optdata can be NULL
size_t set_option(unsigned char *buf, size_t buflen, unsigned char code,
				  unsigned char *optdata, size_t datalen)
{
	if (!optdata)
		datalen = 0;
	if (code == DHCP_PADDING || code == DHCP_END) {
		if (buflen < 1)
			return 0;
		buf[0] = code;
		return 1;
	}

	if (datalen > 255 || buflen < 2 + datalen)
		return 0;
	buf[0] = code;
	buf[1] = datalen;
	memcpy(buf + 2, optdata, datalen);
	return 2 + datalen;
}

unsigned char *alloc_option(unsigned char code, unsigned char *optdata,
							size_t datalen)
{
	unsigned char *ret;
	size_t len = sizeof_option(code, datalen);
	ret = xmalloc(len);
	set_option(ret, len, code, optdata, datalen);
	return ret;
}

// This is tricky -- the data must be prefixed by one byte indicating the
// type of ARP MAC address (1 for ethernet) or 0 for a purely symbolic
// identifier.
unsigned char *alloc_dhcp_client_id_option(unsigned char type,
										   unsigned char *idstr, size_t idstrlen)
{
	unsigned char data[idstrlen + 1];
	data[0] = type;
	memcpy(data + 1, idstr, idstrlen);
	return alloc_option(DHCP_CLIENT_ID, data, sizeof data);
}

// Worker function for get_option().  Optlen will be set to the length
// of the option data.
static uint8_t *do_get_option(uint8_t *buf, ssize_t buflen, int code,
							  char *overload, ssize_t *optlen)
{
	/* option bytes: [code][len]([data1][data2]..[dataLEN]) */
	*overload = 0;
	while (buflen > 0) {
		// Advance over padding.
		if (buf[0] == DHCP_PADDING) {
			buflen--;
			buf++;
			continue;
		}

		// We hit the end.
		if (buf[0] == DHCP_END) {
			*optlen = 0;
			return NULL;
		}

		buflen -= buf[1] + 2;
		if (buflen < 0) {
			log_warning("Bad dhcp data: option length would exceed options field length");
			*optlen = 0;
			return NULL;
		}

		if (buf[0] == code) {
			*optlen = buf[1];
			return buf + 2;
		}

		if (buf[0] == DHCP_OPTION_OVERLOAD) {
			if (buf[1] == 1)
				*overload |= buf[2];
			/* fall through */
		}
		buf += buf[1] + 2;
	}
	log_warning("Bad dhcp data: unmarked end of options field");
	*optlen = 0;
	return NULL;
}

// Get an option with bounds checking (warning, result is not aligned)
// optlen will be equal to the length of the option data.
uint8_t *get_option(struct dhcpMessage *packet, int code, ssize_t *optlen)
{
	uint8_t *option, *buf;
	ssize_t buflen;
	char overload, parsed_ff = 0;

	buf = packet->options;
	buflen = sizeof packet->options;

	option = do_get_option(buf, buflen, code, &overload, optlen);
	if (option)
		return option;

	if (overload & 1) {
		parsed_ff = 1;
		option = do_get_option(packet->file, sizeof packet->file,
							   code, &overload, optlen);
		if (option)
			return option;
	}
	if (overload & 2) {
		option = do_get_option(packet->sname, sizeof packet->sname,
							   code, &overload, optlen);
		if (option)
			return option;
		if (!parsed_ff && overload & 1)
			option = do_get_option(packet->file, sizeof packet->file,
								   code, &overload, optlen);
	}
	return option;
}

/* return the position of the 'end' option */
int end_option(uint8_t *optionptr)
{
	int i = 0;

	while (i < DHCP_OPTIONS_BUFSIZE && optionptr[i] != DHCP_END) {
		if (optionptr[i] != DHCP_PADDING)
			i += optionptr[i + OPT_LEN] + OPT_DATA - 1;
		i++;
	}
	return (i < DHCP_OPTIONS_BUFSIZE - 1 ? i : DHCP_OPTIONS_BUFSIZE - 1);
}


/* add an option string to the options (an option string contains an option
 * code, length, then data) */
int add_option_string(unsigned char *optionptr, unsigned char *string)
{
	int end = end_option(optionptr);

	/* end position + string length + option code/length + end option */
	if (end + string[OPT_LEN] + 2 + 1 >= DHCP_OPTIONS_BUFSIZE) {
		log_error("Option 0x%02x did not fit into the packet!",
				  string[OPT_CODE]);
		return 0;
	}
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
			length = option_length(options[i].type);
		}

	log_line("aso(): code=0x%02x length=0x%02x", code, length);
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

/* Add a paramater request list for stubborn DHCP servers.  Don't do bounds */
/* checking here because it goes towards the head of the packet. */
void add_requests(struct dhcpMessage *packet)
{
    int end = end_option(packet->options);
    int i, len = 0;

    packet->options[end + OPT_CODE] = DHCP_PARAM_REQ;
    for (i = 0; req_opts[i]; i++)
		packet->options[end + OPT_DATA + len++] = req_opts[i];
    packet->options[end + OPT_LEN] = len;
    packet->options[end + OPT_DATA + len] = DHCP_END;
}
