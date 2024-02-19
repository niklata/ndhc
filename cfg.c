#line 1 "cfg.rl"
// Copyright 2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "ndhc-defines.h"
#include "cfg.h"
#include "sys.h"
#include "arp.h"
#include "ndhc.h"
#include "ifchd.h"
#include "sockd.h"
#include "nk/log.h"
#include "nk/privs.h"
#include "nk/io.h"

static bool xisxdigit(int c)
{
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static bool is_string_hwaddr(const char *str, size_t slen)
{
	return slen == 17 && str[2] == ':' && str[5] == ':' && str[8] == ':' &&
	str[11] == ':' && str[14] == ':' &&
	xisxdigit(str[0]) && xisxdigit(str[1]) && xisxdigit(str[3]) &&
	xisxdigit(str[4]) && xisxdigit(str[6]) && xisxdigit(str[7]) &&
	xisxdigit(str[9]) && xisxdigit(str[10]) && xisxdigit(str[12]) &&
	xisxdigit(str[13]) && xisxdigit(str[15]) && xisxdigit(str[16]);
}

static int get_clientid_string(const char *str, size_t slen)
{
	if (!slen)
		return -1;
	if (!is_string_hwaddr(str, slen)) {
		client_config.clientid[0] = 0;
		memcpy(client_config.clientid + 1, str,
		min_size_t(slen, sizeof client_config.clientid - 1));
		client_config.clientid_len = slen + 1;
		return 0;
	}
	
	uint8_t mac[6];
	for (size_t i = 0; i < sizeof mac; ++i)
	mac[i] = strtol(str+i*3, (char **)0, 16);
	client_config.clientid[0] = 1; // Ethernet MAC type
	memcpy(client_config.clientid + 1, mac,
	min_size_t(sizeof mac, sizeof client_config.clientid - 1));
	client_config.clientid_len = 7;
	return 1;
}

static void copy_cmdarg(char *dest, const char *src,
size_t destlen, const char *argname)
{
	if (!memccpy(dest, src, 0, destlen))
		suicide("snprintf failed on %s\n", argname);
}

struct cfgparse {
	char buf[MAX_BUF];
	size_t buflen;
	int ternary; // = 0 nothing, -1 = false, +1 = true
	int cs;
};


#line 211 "cfg.rl"



#line 260 "cfg.rl"



#line 79 "cfg.c"
static const signed char _file_cfg_actions[] = {
	0, 1, 1, 2, 0, 1, 2, 2,
	5, 2, 2, 6, 2, 2, 7, 2,
	2, 9, 2, 2, 10, 2, 2, 11,
	2, 2, 12, 2, 2, 13, 2, 2,
	14, 2, 2, 15, 2, 2, 16, 2,
	2, 19, 2, 2, 20, 2, 2, 21,
	2, 2, 22, 2, 2, 23, 2, 2,
	24, 2, 2, 26, 2, 2, 27, 2,
	3, 8, 2, 3, 17, 2, 3, 18,
	2, 3, 25, 2, 4, 8, 2, 4,
	17, 2, 4, 18, 2, 4, 25, 0
};

static const char _file_cfg_trans_keys[] = {
	1, 0, 1, 28, 24, 24, 22, 22,
	3, 3, 22, 22, 24, 24, 21, 21,
	9, 9, 12, 12, 3, 3, 19, 29,
	8, 16, 30, 30, 0, 7, 0, 1,
	1, 1, 0, 1, 20, 20, 0, 7,
	0, 1, 1, 1, 0, 1, 27, 27,
	19, 19, 0, 7, 0, 1, 1, 1,
	0, 1, 8, 8, 16, 16, 26, 26,
	0, 7, 0, 1, 1, 1, 0, 1,
	15, 18, 24, 24, 21, 21, 21, 21,
	26, 26, 0, 7, 0, 1, 1, 1,
	0, 1, 16, 16, 12, 12, 20, 20,
	26, 26, 16, 16, 11, 11, 0, 7,
	0, 1, 1, 1, 0, 1, 15, 15,
	10, 10, 22, 22, 3, 3, 25, 25,
	12, 12, 26, 26, 3, 3, 15, 15,
	21, 21, 25, 25, 26, 26, 20, 20,
	8, 8, 19, 19, 12, 12, 0, 7,
	0, 26, 1, 1, 1, 1, 8, 8,
	18, 18, 25, 25, 12, 12, 24, 24,
	27, 27, 12, 12, 29, 29, 3, 3,
	19, 19, 12, 12, 26, 26, 24, 24,
	16, 16, 10, 10, 0, 7, 0, 1,
	1, 1, 0, 1, 21, 21, 25, 25,
	26, 26, 20, 20, 8, 8, 19, 19,
	12, 12, 0, 7, 0, 1, 1, 1,
	0, 1, 13, 20, 10, 10, 15, 15,
	3, 3, 27, 27, 25, 25, 12, 12,
	24, 24, 0, 7, 0, 1, 1, 1,
	0, 1, 26, 26, 12, 12, 24, 24,
	13, 13, 8, 8, 10, 10, 12, 12,
	0, 7, 0, 1, 1, 1, 0, 1,
	21, 21, 29, 29, 0, 7, 0, 26,
	1, 1, 1, 1, 8, 8, 18, 18,
	25, 25, 12, 12, 24, 24, 27, 27,
	12, 12, 12, 13, 18, 25, 12, 12,
	20, 20, 26, 26, 18, 18, 12, 12,
	25, 25, 25, 25, 3, 3, 11, 11,
	12, 12, 13, 13, 12, 12, 20, 20,
	25, 25, 12, 12, 0, 7, 0, 26,
	1, 1, 1, 1, 8, 8, 18, 18,
	25, 25, 12, 12, 24, 24, 27, 27,
	12, 12, 27, 27, 12, 12, 25, 25,
	26, 26, 0, 7, 0, 1, 1, 1,
	0, 1, 21, 21, 18, 18, 28, 28,
	3, 3, 10, 10, 21, 21, 20, 20,
	13, 13, 0, 7, 0, 1, 1, 1,
	0, 1, 17, 17, 16, 16, 18, 18,
	18, 18, 3, 3, 16, 16, 11, 11,
	30, 30, 0, 7, 0, 1, 1, 1,
	0, 1, 6, 26, 3, 3, 20, 20,
	21, 21, 26, 26, 16, 16, 13, 13,
	31, 31, 0, 7, 0, 1, 1, 1,
	0, 1, 24, 24, 16, 16, 22, 22,
	26, 26, 3, 3, 13, 13, 16, 16,
	18, 18, 12, 12, 0, 7, 0, 1,
	1, 1, 0, 1, 10, 10, 10, 10,
	21, 21, 19, 19, 22, 22, 3, 3,
	12, 12, 20, 20, 13, 13, 21, 21,
	24, 24, 10, 10, 12, 12, 0, 7,
	0, 26, 1, 1, 1, 1, 8, 8,
	18, 18, 25, 25, 12, 12, 24, 24,
	27, 27, 12, 12, 10, 10, 17, 17,
	11, 11, 3, 3, 27, 27, 25, 25,
	12, 12, 24, 24, 0, 7, 0, 1,
	1, 1, 0, 1, 8, 8, 26, 26,
	12, 12, 3, 3, 11, 11, 16, 16,
	24, 24, 0, 7, 0, 1, 1, 1,
	0, 1, 25, 25, 12, 12, 24, 24,
	0, 7, 0, 1, 1, 1, 0, 1,
	12, 12, 20, 20, 11, 11, 21, 21,
	24, 24, 16, 16, 11, 11, 0, 7,
	0, 1, 1, 1, 0, 1, 1, 0,
	0
};

static const signed char _file_cfg_char_class[] = {
	0, 1, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 0,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 3, 2, 2, 4,
	5, 2, 2, 2, 2, 6, 2, 2,
	2, 2, 2, 2, 7, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2,
	8, 9, 10, 11, 12, 13, 14, 15,
	16, 2, 17, 18, 19, 20, 21, 22,
	23, 24, 25, 26, 27, 28, 29, 30,
	31, 0
};

static const short _file_cfg_index_offsets[] = {
	0, 0, 28, 29, 30, 31, 32, 33,
	34, 35, 36, 37, 48, 57, 58, 66,
	68, 69, 71, 72, 80, 82, 83, 85,
	86, 87, 95, 97, 98, 100, 101, 102,
	103, 111, 113, 114, 116, 120, 121, 122,
	123, 124, 132, 134, 135, 137, 138, 139,
	140, 141, 142, 143, 151, 153, 154, 156,
	157, 158, 159, 160, 161, 162, 163, 164,
	165, 166, 167, 168, 169, 170, 171, 172,
	180, 207, 208, 209, 210, 211, 212, 213,
	214, 215, 216, 217, 218, 219, 220, 221,
	222, 223, 224, 232, 234, 235, 237, 238,
	239, 240, 241, 242, 243, 244, 252, 254,
	255, 257, 265, 266, 267, 268, 269, 270,
	271, 272, 280, 282, 283, 285, 286, 287,
	288, 289, 290, 291, 292, 300, 302, 303,
	305, 306, 307, 315, 342, 343, 344, 345,
	346, 347, 348, 349, 350, 351, 353, 361,
	362, 363, 364, 365, 366, 367, 368, 369,
	370, 371, 372, 373, 374, 375, 376, 384,
	411, 412, 413, 414, 415, 416, 417, 418,
	419, 420, 421, 422, 423, 424, 432, 434,
	435, 437, 438, 439, 440, 441, 442, 443,
	444, 445, 453, 455, 456, 458, 459, 460,
	461, 462, 463, 464, 465, 466, 474, 476,
	477, 479, 500, 501, 502, 503, 504, 505,
	506, 507, 515, 517, 518, 520, 521, 522,
	523, 524, 525, 526, 527, 528, 529, 537,
	539, 540, 542, 543, 544, 545, 546, 547,
	548, 549, 550, 551, 552, 553, 554, 555,
	563, 590, 591, 592, 593, 594, 595, 596,
	597, 598, 599, 600, 601, 602, 603, 604,
	605, 606, 607, 615, 617, 618, 620, 621,
	622, 623, 624, 625, 626, 627, 635, 637,
	638, 640, 641, 642, 643, 651, 653, 654,
	656, 657, 658, 659, 660, 661, 662, 663,
	671, 673, 674, 676, 0
};

static const short _file_cfg_indices[] = {
	2, 0, 0, 0, 0, 0, 0, 3,
	0, 4, 5, 0, 0, 6, 7, 8,
	0, 0, 0, 9, 0, 0, 0, 10,
	11, 0, 12, 13, 14, 15, 16, 17,
	18, 19, 20, 21, 22, 23, 24, 0,
	0, 0, 0, 0, 0, 0, 0, 25,
	26, 0, 0, 0, 0, 0, 0, 0,
	27, 28, 28, 0, 0, 0, 0, 0,
	0, 29, 31, 0, 34, 31, 34, 36,
	36, 0, 0, 0, 0, 0, 0, 37,
	39, 0, 42, 39, 42, 44, 45, 45,
	0, 0, 0, 0, 0, 0, 46, 48,
	0, 51, 48, 51, 53, 54, 55, 55,
	0, 0, 0, 0, 0, 0, 56, 58,
	0, 61, 58, 61, 63, 0, 0, 64,
	65, 66, 67, 68, 68, 0, 0, 0,
	0, 0, 0, 69, 71, 0, 74, 71,
	74, 76, 77, 78, 79, 80, 81, 81,
	0, 0, 0, 0, 0, 0, 82, 84,
	0, 87, 84, 87, 89, 90, 91, 92,
	93, 94, 95, 96, 97, 98, 99, 100,
	101, 102, 103, 104, 104, 0, 0, 0,
	0, 0, 0, 105, 105, 0, 0, 0,
	106, 107, 0, 0, 0, 0, 0, 0,
	0, 108, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 109, 110,
	111, 112, 113, 114, 106, 115, 116, 107,
	117, 118, 119, 120, 121, 122, 123, 124,
	124, 0, 0, 0, 0, 0, 0, 125,
	127, 0, 130, 127, 130, 132, 133, 134,
	135, 136, 137, 138, 138, 0, 0, 0,
	0, 0, 0, 139, 141, 0, 144, 141,
	144, 146, 0, 0, 0, 0, 0, 0,
	147, 148, 149, 150, 151, 152, 153, 154,
	154, 0, 0, 0, 0, 0, 0, 155,
	157, 0, 160, 157, 160, 162, 163, 164,
	165, 166, 167, 168, 168, 0, 0, 0,
	0, 0, 0, 169, 171, 0, 174, 171,
	174, 176, 177, 177, 0, 0, 0, 0,
	0, 0, 178, 178, 0, 0, 0, 179,
	180, 0, 0, 0, 0, 0, 0, 0,
	181, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 182, 183, 184,
	185, 186, 187, 179, 188, 189, 180, 190,
	191, 192, 0, 0, 0, 0, 193, 0,
	194, 195, 196, 197, 198, 199, 200, 201,
	202, 203, 204, 205, 206, 207, 208, 209,
	209, 0, 0, 0, 0, 0, 0, 210,
	210, 0, 0, 0, 211, 212, 0, 0,
	0, 0, 0, 0, 0, 213, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 214, 215, 216, 217, 218, 219,
	211, 220, 221, 212, 222, 223, 224, 225,
	225, 0, 0, 0, 0, 0, 0, 226,
	228, 0, 231, 228, 231, 233, 234, 235,
	236, 237, 238, 239, 240, 240, 0, 0,
	0, 0, 0, 0, 241, 243, 0, 246,
	243, 246, 248, 249, 250, 251, 252, 253,
	254, 255, 255, 0, 0, 0, 0, 0,
	0, 256, 258, 0, 261, 258, 261, 263,
	0, 0, 0, 264, 0, 265, 0, 0,
	0, 0, 0, 0, 0, 0, 266, 0,
	0, 0, 0, 267, 268, 269, 270, 271,
	272, 273, 274, 274, 0, 0, 0, 0,
	0, 0, 275, 277, 0, 280, 277, 280,
	282, 283, 284, 285, 286, 287, 288, 289,
	290, 290, 0, 0, 0, 0, 0, 0,
	291, 293, 0, 296, 293, 296, 298, 299,
	300, 301, 302, 303, 304, 305, 306, 307,
	308, 309, 310, 310, 0, 0, 0, 0,
	0, 0, 311, 311, 0, 0, 0, 312,
	313, 0, 0, 0, 0, 0, 0, 0,
	314, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 315, 316, 317,
	318, 319, 320, 312, 321, 322, 313, 323,
	324, 325, 326, 327, 328, 329, 330, 330,
	0, 0, 0, 0, 0, 0, 331, 333,
	0, 336, 333, 336, 338, 339, 340, 341,
	342, 343, 344, 344, 0, 0, 0, 0,
	0, 0, 345, 347, 0, 350, 347, 350,
	352, 353, 354, 354, 0, 0, 0, 0,
	0, 0, 355, 357, 0, 360, 357, 360,
	362, 363, 364, 365, 366, 367, 368, 368,
	0, 0, 0, 0, 0, 0, 369, 371,
	0, 374, 371, 374, 0
};

static const short _file_cfg_index_defaults[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 30,
	33, 30, 0, 0, 38, 41, 38, 0,
	0, 0, 47, 50, 47, 0, 0, 0,
	0, 57, 60, 57, 0, 0, 0, 0,
	0, 0, 70, 73, 70, 0, 0, 0,
	0, 0, 0, 0, 83, 86, 83, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 126, 129, 126, 0, 0,
	0, 0, 0, 0, 0, 0, 140, 143,
	140, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 156, 159, 156, 0, 0, 0,
	0, 0, 0, 0, 0, 170, 173, 170,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 227, 230,
	227, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 242, 245, 242, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 257, 260,
	257, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 276, 279, 276, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 292,
	295, 292, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 332, 335, 332, 0, 0,
	0, 0, 0, 0, 0, 0, 346, 349,
	346, 0, 0, 0, 0, 356, 359, 356,
	0, 0, 0, 0, 0, 0, 0, 0,
	370, 373, 370, 0, 0
};

static const short _file_cfg_cond_targs[] = {
	0, 1, 291, 2, 36, 55, 82, 94,
	105, 128, 141, 201, 273, 280, 3, 4,
	5, 6, 7, 8, 9, 10, 11, 12,
	23, 29, 13, 18, 14, 15, 16, 17,
	16, 16, 291, 17, 19, 20, 21, 22,
	21, 21, 291, 22, 24, 25, 26, 27,
	28, 27, 27, 291, 28, 30, 31, 32,
	33, 34, 35, 34, 34, 291, 35, 37,
	45, 38, 39, 40, 41, 42, 43, 44,
	43, 43, 291, 44, 46, 47, 48, 49,
	50, 51, 52, 53, 54, 53, 53, 291,
	54, 56, 57, 58, 59, 60, 61, 62,
	63, 64, 65, 66, 67, 68, 69, 70,
	71, 72, 73, 74, 75, 79, 291, 291,
	76, 77, 78, 80, 81, 83, 84, 85,
	86, 87, 88, 89, 90, 91, 92, 93,
	92, 92, 291, 93, 95, 96, 97, 98,
	99, 100, 101, 102, 103, 104, 103, 103,
	291, 104, 106, 117, 107, 108, 109, 110,
	111, 112, 113, 114, 115, 116, 115, 115,
	291, 116, 118, 119, 120, 121, 122, 123,
	124, 125, 126, 127, 126, 126, 291, 127,
	129, 130, 131, 132, 133, 134, 138, 291,
	291, 135, 136, 137, 139, 140, 142, 189,
	143, 169, 177, 144, 145, 146, 147, 148,
	149, 150, 151, 152, 153, 154, 155, 156,
	157, 158, 159, 160, 161, 162, 166, 291,
	291, 163, 164, 165, 167, 168, 170, 171,
	172, 173, 174, 175, 176, 175, 175, 291,
	176, 178, 179, 180, 181, 182, 183, 184,
	185, 186, 187, 188, 187, 187, 291, 188,
	190, 191, 192, 193, 194, 195, 196, 197,
	198, 199, 200, 199, 199, 291, 200, 202,
	213, 226, 250, 262, 203, 204, 205, 206,
	207, 208, 209, 210, 211, 212, 211, 211,
	291, 212, 214, 215, 216, 217, 218, 219,
	220, 221, 222, 223, 224, 225, 224, 224,
	291, 225, 227, 228, 229, 230, 231, 232,
	233, 234, 235, 236, 237, 238, 239, 240,
	241, 242, 243, 247, 291, 291, 244, 245,
	246, 248, 249, 251, 252, 253, 254, 255,
	256, 257, 258, 259, 260, 261, 260, 260,
	291, 261, 263, 264, 265, 266, 267, 268,
	269, 270, 271, 272, 271, 271, 291, 272,
	274, 275, 276, 277, 278, 279, 278, 278,
	291, 279, 281, 282, 283, 284, 285, 286,
	287, 288, 289, 290, 289, 289, 291, 290,
	0
};

static const signed char _file_cfg_cond_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 3, 3,
	0, 1, 48, 0, 0, 0, 3, 3,
	0, 1, 45, 0, 0, 0, 0, 3,
	3, 0, 1, 42, 0, 0, 0, 0,
	0, 3, 3, 0, 1, 39, 0, 0,
	0, 0, 0, 0, 0, 0, 3, 3,
	0, 1, 30, 0, 0, 0, 0, 0,
	0, 0, 0, 3, 3, 0, 1, 6,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 84, 72,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 3, 3,
	0, 1, 51, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 3, 3, 0, 1,
	9, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 3, 3, 0, 1,
	24, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 3, 3, 0, 1, 12, 0,
	0, 0, 0, 0, 0, 0, 0, 75,
	63, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 81,
	69, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 3, 3, 0, 1, 15,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 3, 3, 0, 1, 54, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 3, 3, 0, 1, 57, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 3, 3, 0, 1,
	60, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 3, 3, 0, 1,
	36, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 78, 66, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 3, 3, 0, 1,
	27, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 3, 3, 0, 1, 33, 0,
	0, 0, 0, 0, 3, 3, 0, 1,
	21, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 3, 3, 0, 1, 18, 0,
	0
};

static const int file_cfg_start = 1;
static const int file_cfg_first_final = 291;
static const int file_cfg_error = 0;

static const int file_cfg_en_main = 1;


#line 262 "cfg.rl"


static void parse_cfgfile(const char *fname)
{
	bool reached_eof = false;
	struct cfgparse ccfg;
	memset(&ccfg, 0, sizeof ccfg);
	char l[MAX_BUF];
	size_t lc = 0;
	memset(l, 0, sizeof l);
	int fd = open(fname, O_RDONLY|O_CLOEXEC, 0);
	if (fd < 0)
		suicide("Unable to open config file '%s'.\n", fname);
	
	size_t linenum = 0;
	for (;;) {
		if (lc + 1 >= sizeof l) suicide("sizeof l - 1 - lc would underflow\n");
			ssize_t rc = safe_read(fd, l + lc, sizeof l - 1 - lc);
		if (rc < 0)
			suicide("Error reading config file '%s'.\n", fname);
		if (rc == 0) {
			l[lc] = '\n'; rc = 1; reached_eof = true; // Emulate a LF to terminate the line.
		}
		lc += (size_t)rc;
		
		size_t lstart = 0, lend = 0, consumed = 0;
		for (; lend < lc; ++lend) {
			if (l[lend] == '\n') {
				++linenum; consumed = lend;
				
				size_t llen = lend - lstart;
				const char *p = l + lstart;
				const char *pe = l + lstart + llen + 1;

#line 498 "cfg.c"
	{
					ccfg.cs = (int)file_cfg_start;
				}
				
#line 295 "cfg.rl"


#line 503 "cfg.c"
	{
					unsigned int _trans = 0;
					const char * _keys;
					const signed char * _acts;
					const short * _inds;
					unsigned int _nacts;
					int _ic;
					_resume: {}
					if ( p == pe )
						goto _out;
					_keys = ( _file_cfg_trans_keys + ((ccfg.cs<<1)));
					_inds = ( _file_cfg_indices + (_file_cfg_index_offsets[ccfg.cs]));
					
					if ( ( (*( p))) <= 121 && ( (*( p))) >= 9 ) {
						_ic = (int)_file_cfg_char_class[(int)( (*( p))) - 9];
						if ( _ic <= (int)(*( _keys+1)) && _ic >= (int)(*( _keys)) )
							_trans = (unsigned int)(*( _inds + (int)( _ic - (int)(*( _keys)) ) )); 
						else
							_trans = (unsigned int)_file_cfg_index_defaults[ccfg.cs];
					}
					else {
						_trans = (unsigned int)_file_cfg_index_defaults[ccfg.cs];
					}
					
					ccfg.cs = (int)_file_cfg_cond_targs[_trans];
					
					if ( _file_cfg_cond_actions[_trans] != 0 ) {
						
						_acts = ( _file_cfg_actions + (_file_cfg_cond_actions[_trans]));
						_nacts = (unsigned int)(*( _acts));
						_acts += 1;
						while ( _nacts > 0 ) {
							switch ( (*( _acts)) )
							{
								case 0:  {
										{
#line 76 "cfg.rl"
										
										memset(&ccfg.buf, 0, sizeof ccfg.buf);
										ccfg.buflen = 0;
										ccfg.ternary = 0;
									}
									
#line 546 "cfg.c"

									break; 
								}
								case 1:  {
										{
#line 81 "cfg.rl"
										
										if (ccfg.buflen < sizeof ccfg.buf - 1)
										ccfg.buf[ccfg.buflen++] = *p;
										else
										suicide("line or option is too long\n");
									}
									
#line 559 "cfg.c"

									break; 
								}
								case 2:  {
										{
#line 87 "cfg.rl"
										
										if (ccfg.buflen < sizeof ccfg.buf)
										ccfg.buf[ccfg.buflen] = 0;
									}
									
#line 570 "cfg.c"

									break; 
								}
								case 3:  {
										{
#line 91 "cfg.rl"
										ccfg.ternary = 1; }
									
#line 578 "cfg.c"

									break; 
								}
								case 4:  {
										{
#line 92 "cfg.rl"
										ccfg.ternary = -1; }
									
#line 586 "cfg.c"

									break; 
								}
								case 5:  {
										{
#line 94 "cfg.rl"
										get_clientid_string(ccfg.buf, ccfg.buflen); }
									
#line 594 "cfg.c"

									break; 
								}
								case 6:  {
										{
#line 95 "cfg.rl"
										
										copy_cmdarg(client_config.hostname, ccfg.buf,
										sizeof client_config.hostname, "hostname");
									}
									
#line 605 "cfg.c"

									break; 
								}
								case 7:  {
										{
#line 99 "cfg.rl"
										
										copy_cmdarg(client_config.interface, ccfg.buf,
										sizeof client_config.interface, "interface");
									}
									
#line 616 "cfg.c"

									break; 
								}
								case 8:  {
										{
#line 103 "cfg.rl"
										
										switch (ccfg.ternary) {
											case 1: client_config.abort_if_no_lease = true; break;
											case -1: client_config.abort_if_no_lease = false; default: break;
										}
									}
									
#line 629 "cfg.c"

									break; 
								}
								case 9:  {
										{
#line 109 "cfg.rl"
										set_client_addr(ccfg.buf); }
									
#line 637 "cfg.c"

									break; 
								}
								case 10:  {
										{
#line 110 "cfg.rl"
										
										copy_cmdarg(client_config.vendor, ccfg.buf,
										sizeof client_config.vendor, "vendorid");
									}
									
#line 648 "cfg.c"

									break; 
								}
								case 11:  {
										{
#line 114 "cfg.rl"
										
										if (nk_uidgidbyname(ccfg.buf, &ndhc_uid, &ndhc_gid))
										suicide("invalid ndhc user '%s' specified\n", ccfg.buf);
									}
									
#line 659 "cfg.c"

									break; 
								}
								case 12:  {
										{
#line 118 "cfg.rl"
										
										if (nk_uidgidbyname(ccfg.buf, &ifch_uid, &ifch_gid))
										suicide("invalid ifch user '%s' specified\n", ccfg.buf);
									}
									
#line 670 "cfg.c"

									break; 
								}
								case 13:  {
										{
#line 122 "cfg.rl"
										
										if (nk_uidgidbyname(ccfg.buf, &sockd_uid, &sockd_gid))
										suicide("invalid sockd user '%s' specified\n", ccfg.buf);
									}
									
#line 681 "cfg.c"

									break; 
								}
								case 14:  {
										{
#line 126 "cfg.rl"
										
										copy_cmdarg(chroot_dir, ccfg.buf, sizeof chroot_dir, "chroot");
									}
									
#line 691 "cfg.c"

									break; 
								}
								case 15:  {
										{
#line 129 "cfg.rl"
										
										copy_cmdarg(state_dir, ccfg.buf, sizeof state_dir, "state-dir");
									}
									
#line 701 "cfg.c"

									break; 
								}
								case 16:  {
										{
#line 132 "cfg.rl"
										
										copy_cmdarg(script_file, ccfg.buf, sizeof script_file, "script-file");
									}
									
#line 711 "cfg.c"

									break; 
								}
								case 17:  {
										{
#line 135 "cfg.rl"
										
										log_line("seccomp_enforce option is deprecated; please remove it\n"
										"In the meanwhile, it is ignored and seccomp is disabled.\n");
									}
									
#line 722 "cfg.c"

									break; 
								}
								case 18:  {
										{
#line 139 "cfg.rl"
										
										switch (ccfg.ternary) {
											case 1: set_arp_relentless_def(true); break;
											case -1: set_arp_relentless_def(false); default: break;
										}
									}
									
#line 735 "cfg.c"

									break; 
								}
								case 19:  {
										{
#line 145 "cfg.rl"
										
										int t = atoi(ccfg.buf);
										if (t >= 0)
										arp_probe_wait = (unsigned)t;
									}
									
#line 747 "cfg.c"

									break; 
								}
								case 20:  {
										{
#line 150 "cfg.rl"
										
										int t = atoi(ccfg.buf);
										if (t >= 0)
										arp_probe_num = (unsigned)t;
									}
									
#line 759 "cfg.c"

									break; 
								}
								case 21:  {
										{
#line 155 "cfg.rl"
										
										int ti = atoi(ccfg.buf);
										if (ti >= 0) {
											unsigned t = (unsigned)ti;
											arp_probe_min = t;
											if (arp_probe_min > arp_probe_max) {
												t = arp_probe_max;
												arp_probe_max = arp_probe_min;
												arp_probe_min = t;
											}
										}
									}
									
#line 778 "cfg.c"

									break; 
								}
								case 22:  {
										{
#line 167 "cfg.rl"
										
										int ti = atoi(ccfg.buf);
										if (ti >= 0) {
											unsigned t = (unsigned)ti;
											arp_probe_max = t;
											if (arp_probe_min > arp_probe_max) {
												t = arp_probe_max;
												arp_probe_max = arp_probe_min;
												arp_probe_min = t;
											}
										}
									}
									
#line 797 "cfg.c"

									break; 
								}
								case 23:  {
										{
#line 179 "cfg.rl"
										
										char *q;
										long mt = strtol(ccfg.buf, &q, 10);
										if (q == ccfg.buf)
										suicide("gw-metric arg '%s' isn't a valid number\n", ccfg.buf);
										if (mt > INT_MAX)
										suicide("gw-metric arg '%s' is too large\n", ccfg.buf);
										if (mt < 0)
										mt = 0;
										client_config.metric = (int)mt;
									}
									
#line 815 "cfg.c"

									break; 
								}
								case 24:  {
										{
#line 190 "cfg.rl"
										
										copy_cmdarg(resolv_conf_d, ccfg.buf, sizeof resolv_conf_d,
										"resolv-conf");
									}
									
#line 826 "cfg.c"

									break; 
								}
								case 25:  {
										{
#line 194 "cfg.rl"
										
										switch (ccfg.ternary) {
											case 1: allow_hostname = 1; break;
											case -1: allow_hostname = 0; default: break;
										}
									}
									
#line 839 "cfg.c"

									break; 
								}
								case 26:  {
										{
#line 200 "cfg.rl"
										
										uint32_t t = (uint32_t)atoi(ccfg.buf);
										client_config.rfkillIdx = t;
										client_config.enable_rfkill = true;
									}
									
#line 851 "cfg.c"

									break; 
								}
								case 27:  {
										{
#line 205 "cfg.rl"
										
										client_config.s6_notify_fd = atoi(ccfg.buf);
										client_config.enable_s6_notify = true;
									}
									
#line 862 "cfg.c"

									break; 
								}
							}
							_nacts -= 1;
							_acts += 1;
						}
						
					}
					
					if ( ccfg.cs != 0 ) {
						p += 1;
						goto _resume;
					}
					_out: {}
				}
				
#line 296 "cfg.rl"

				
				if (ccfg.cs == file_cfg_error)
					suicide("error parsing config file line %zu: malformed\n", linenum);
				if (ccfg.cs < file_cfg_first_final)
					suicide("error parsing config file line %zu: incomplete\n", linenum);
				lstart = lend + 1;
			}
		}
		if (reached_eof)
			break;
		if (!consumed && lend >= sizeof l - 1)
			suicide("Line %zu in config file '%s' is too long: %zu > %zu.\n",
		linenum, fname, lend, sizeof l - 1);
		
		if (consumed + 1 > lc) suicide("lc[%zu] - consumed[%zu] would underflow\n", lc, lend);
			if (consumed) {
			memmove(l, l + consumed + 1, lc - consumed - 1);
			lc -= consumed + 1;
		}
	}
	close(fd);
}


#line 366 "cfg.rl"



#line 906 "cfg.c"
static const signed char _cmd_cfg_actions[] = {
	0, 1, 1, 1, 6, 1, 15, 1,
	16, 1, 23, 1, 26, 1, 27, 1,
	29, 2, 0, 1, 2, 2, 3, 2,
	2, 4, 2, 2, 5, 2, 2, 7,
	2, 2, 8, 2, 2, 9, 2, 2,
	10, 2, 2, 11, 2, 2, 12, 2,
	2, 13, 2, 2, 14, 2, 2, 17,
	2, 2, 18, 2, 2, 19, 2, 2,
	20, 2, 2, 21, 2, 2, 22, 2,
	2, 24, 2, 2, 25, 2, 2, 28,
	0
};

static const char _cmd_cfg_trans_keys[] = {
	1, 0, 2, 39, 18, 38, 34, 34,
	32, 32, 2, 2, 32, 32, 34, 34,
	31, 31, 19, 19, 22, 22, 2, 2,
	29, 39, 18, 26, 40, 40, 0, 0,
	0, 0, 0, 0, 30, 30, 0, 0,
	0, 0, 0, 0, 37, 37, 29, 29,
	0, 0, 0, 0, 0, 0, 18, 18,
	26, 26, 36, 36, 0, 0, 0, 0,
	0, 0, 25, 31, 34, 34, 31, 31,
	31, 31, 36, 36, 0, 0, 0, 0,
	0, 0, 26, 26, 22, 22, 30, 30,
	36, 36, 26, 26, 21, 21, 0, 0,
	0, 0, 0, 0, 30, 30, 23, 23,
	26, 26, 24, 24, 0, 0, 0, 0,
	0, 0, 25, 25, 20, 20, 32, 32,
	2, 2, 35, 35, 22, 22, 36, 36,
	2, 2, 25, 25, 31, 31, 35, 35,
	36, 36, 30, 30, 18, 18, 29, 29,
	22, 22, 0, 0, 39, 39, 2, 2,
	29, 29, 22, 22, 36, 36, 34, 34,
	26, 26, 20, 20, 0, 0, 0, 0,
	0, 0, 22, 31, 28, 28, 32, 32,
	0, 0, 35, 35, 36, 36, 30, 30,
	18, 18, 29, 29, 22, 22, 0, 0,
	0, 0, 0, 0, 23, 30, 20, 20,
	25, 25, 2, 2, 37, 37, 35, 35,
	22, 22, 34, 34, 0, 0, 0, 0,
	0, 0, 36, 36, 22, 22, 34, 34,
	23, 23, 18, 18, 20, 20, 22, 22,
	0, 0, 0, 0, 0, 0, 31, 31,
	39, 39, 0, 0, 22, 23, 28, 35,
	22, 22, 30, 30, 36, 36, 28, 28,
	22, 22, 35, 35, 35, 35, 2, 2,
	21, 21, 22, 22, 23, 23, 22, 22,
	30, 30, 35, 35, 22, 22, 0, 0,
	37, 37, 22, 22, 35, 35, 36, 36,
	0, 0, 0, 0, 0, 0, 31, 31,
	28, 28, 38, 38, 2, 2, 20, 20,
	31, 31, 30, 30, 23, 23, 0, 0,
	0, 0, 0, 0, 27, 27, 26, 26,
	28, 28, 28, 28, 2, 2, 26, 26,
	21, 21, 40, 40, 0, 0, 0, 0,
	0, 0, 3, 36, 2, 2, 30, 30,
	31, 31, 36, 36, 26, 26, 23, 23,
	41, 41, 0, 0, 0, 0, 0, 0,
	34, 34, 26, 26, 32, 32, 36, 36,
	2, 2, 23, 23, 26, 26, 28, 28,
	22, 22, 0, 0, 0, 0, 0, 0,
	20, 20, 20, 20, 31, 31, 29, 29,
	32, 32, 2, 2, 22, 22, 30, 30,
	23, 23, 31, 31, 34, 34, 20, 20,
	22, 22, 0, 0, 20, 20, 27, 27,
	21, 21, 2, 2, 37, 37, 35, 35,
	22, 22, 34, 34, 0, 0, 0, 0,
	0, 0, 18, 18, 36, 36, 22, 22,
	2, 2, 21, 21, 26, 26, 34, 34,
	0, 0, 0, 0, 0, 0, 35, 35,
	22, 22, 34, 34, 0, 0, 0, 0,
	0, 0, 22, 22, 30, 34, 21, 21,
	31, 31, 34, 34, 26, 26, 21, 21,
	0, 0, 0, 0, 0, 0, 35, 35,
	26, 26, 31, 31, 30, 30, 0, 0,
	2, 2, 2, 2, 0
};

static const signed char _cmd_cfg_char_class[] = {
	0, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 2, 1, 1,
	1, 1, 1, 1, 1, 1, 3, 1,
	1, 1, 1, 1, 1, 1, 1, 4,
	1, 1, 1, 5, 6, 1, 1, 1,
	7, 8, 1, 9, 1, 10, 11, 1,
	1, 1, 12, 13, 1, 14, 15, 16,
	17, 1, 1, 1, 1, 1, 1, 1,
	1, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 1, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39,
	40, 41, 0
};

static const short _cmd_cfg_index_offsets[] = {
	0, 0, 38, 59, 60, 61, 62, 63,
	64, 65, 66, 67, 68, 79, 88, 89,
	90, 91, 92, 93, 94, 95, 96, 97,
	98, 99, 100, 101, 102, 103, 104, 105,
	106, 107, 114, 115, 116, 117, 118, 119,
	120, 121, 122, 123, 124, 125, 126, 127,
	128, 129, 130, 131, 132, 133, 134, 135,
	136, 137, 138, 139, 140, 141, 142, 143,
	144, 145, 146, 147, 148, 149, 150, 151,
	152, 153, 154, 155, 156, 157, 158, 159,
	160, 161, 162, 163, 164, 165, 175, 176,
	177, 178, 179, 180, 181, 182, 183, 184,
	185, 186, 187, 195, 196, 197, 198, 199,
	200, 201, 202, 203, 204, 205, 206, 207,
	208, 209, 210, 211, 212, 213, 214, 215,
	216, 217, 218, 220, 228, 229, 230, 231,
	232, 233, 234, 235, 236, 237, 238, 239,
	240, 241, 242, 243, 244, 245, 246, 247,
	248, 249, 250, 251, 252, 253, 254, 255,
	256, 257, 258, 259, 260, 261, 262, 263,
	264, 265, 266, 267, 268, 269, 270, 271,
	272, 273, 307, 308, 309, 310, 311, 312,
	313, 314, 315, 316, 317, 318, 319, 320,
	321, 322, 323, 324, 325, 326, 327, 328,
	329, 330, 331, 332, 333, 334, 335, 336,
	337, 338, 339, 340, 341, 342, 343, 344,
	345, 346, 347, 348, 349, 350, 351, 352,
	353, 354, 355, 356, 357, 358, 359, 360,
	361, 362, 363, 364, 365, 366, 367, 368,
	369, 370, 371, 376, 377, 378, 379, 380,
	381, 382, 383, 384, 385, 386, 387, 388,
	389, 390, 0
};

static const short _cmd_cfg_indices[] = {
	2, 0, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16,
	0, 0, 17, 18, 0, 0, 0, 19,
	20, 0, 0, 21, 22, 0, 0, 0,
	23, 24, 25, 26, 27, 28, 29, 0,
	30, 31, 0, 0, 32, 33, 34, 0,
	0, 0, 35, 0, 0, 0, 36, 37,
	0, 38, 39, 40, 41, 42, 43, 44,
	45, 46, 47, 48, 49, 50, 0, 0,
	0, 0, 0, 0, 0, 0, 51, 52,
	0, 0, 0, 0, 0, 0, 0, 53,
	9, 54, 0, 58, 21, 59, 0, 63,
	64, 15, 65, 0, 69, 70, 71, 28,
	72, 0, 76, 77, 0, 0, 78, 0,
	0, 79, 80, 81, 82, 4, 83, 0,
	87, 88, 89, 90, 91, 92, 7, 93,
	0, 97, 98, 99, 100, 17, 101, 0,
	105, 106, 107, 108, 109, 110, 111, 112,
	113, 114, 115, 116, 117, 118, 119, 120,
	6, 121, 122, 123, 124, 125, 126, 127,
	128, 25, 129, 0, 133, 134, 0, 0,
	0, 0, 0, 0, 0, 0, 135, 136,
	3, 137, 138, 139, 140, 141, 142, 19,
	143, 0, 147, 148, 0, 0, 0, 0,
	0, 0, 149, 150, 151, 152, 153, 154,
	155, 13, 156, 0, 160, 161, 162, 163,
	164, 165, 166, 20, 167, 0, 171, 172,
	22, 173, 174, 175, 176, 0, 0, 0,
	0, 177, 0, 178, 179, 180, 181, 182,
	183, 184, 185, 186, 187, 188, 189, 190,
	191, 192, 18, 193, 194, 195, 196, 23,
	197, 0, 201, 202, 203, 204, 205, 206,
	207, 208, 11, 209, 0, 213, 214, 215,
	216, 217, 218, 219, 220, 8, 221, 0,
	225, 226, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 227, 0, 228, 0, 0, 0,
	0, 0, 0, 0, 0, 229, 0, 0,
	0, 0, 230, 231, 232, 233, 234, 235,
	236, 10, 237, 0, 241, 242, 243, 244,
	245, 246, 247, 248, 249, 16, 250, 0,
	254, 255, 256, 257, 258, 259, 260, 261,
	262, 263, 264, 265, 266, 12, 267, 268,
	269, 270, 271, 272, 273, 274, 5, 275,
	0, 279, 280, 281, 282, 283, 284, 285,
	24, 286, 0, 290, 291, 292, 26, 293,
	0, 297, 298, 299, 0, 0, 0, 300,
	301, 302, 303, 304, 14, 305, 0, 309,
	310, 311, 312, 27, 313, 1, 316, 0
};

static const short _cmd_cfg_index_defaults[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	55, 57, 0, 0, 60, 62, 0, 0,
	0, 66, 68, 0, 0, 0, 0, 73,
	75, 0, 0, 0, 0, 0, 0, 84,
	86, 0, 0, 0, 0, 0, 0, 0,
	94, 96, 0, 0, 0, 0, 0, 102,
	104, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 130, 132, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	144, 146, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 157, 159, 0, 0, 0,
	0, 0, 0, 0, 0, 168, 170, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 198, 200, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 210, 212, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 222,
	224, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 238, 240, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 251, 253,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 276,
	278, 0, 0, 0, 0, 0, 0, 0,
	0, 287, 289, 0, 0, 0, 0, 294,
	296, 0, 0, 0, 0, 0, 0, 0,
	0, 306, 308, 0, 0, 0, 0, 0,
	0, 0, 0
};

static const short _cmd_cfg_cond_targs[] = {
	0, 1, 2, 88, 38, 214, 73, 47,
	166, 15, 177, 155, 205, 106, 240, 24,
	189, 54, 139, 95, 116, 19, 121, 144,
	224, 82, 230, 247, 30, 3, 33, 57,
	74, 85, 98, 119, 122, 169, 227, 233,
	4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 22, 27, 14, 18, 16, 17,
	17, 17, 248, 20, 21, 21, 21, 248,
	23, 25, 26, 26, 26, 248, 28, 29,
	31, 32, 32, 32, 248, 34, 41, 50,
	35, 36, 37, 39, 40, 40, 40, 248,
	42, 43, 44, 45, 46, 48, 49, 49,
	49, 248, 51, 52, 53, 55, 56, 56,
	56, 248, 58, 59, 60, 61, 62, 63,
	64, 65, 66, 67, 68, 69, 70, 71,
	72, 249, 75, 76, 77, 78, 79, 80,
	81, 83, 84, 84, 84, 248, 86, 89,
	87, 248, 90, 91, 92, 93, 94, 96,
	97, 97, 97, 248, 99, 109, 100, 101,
	102, 103, 104, 105, 107, 108, 108, 108,
	248, 110, 111, 112, 113, 114, 115, 117,
	118, 118, 118, 248, 120, 249, 123, 158,
	124, 140, 147, 125, 126, 127, 128, 129,
	130, 131, 132, 133, 134, 135, 136, 137,
	138, 249, 141, 142, 143, 145, 146, 146,
	146, 248, 148, 149, 150, 151, 152, 153,
	154, 156, 157, 157, 157, 248, 159, 160,
	161, 162, 163, 164, 165, 167, 168, 168,
	168, 248, 170, 180, 192, 206, 217, 171,
	172, 173, 174, 175, 176, 178, 179, 179,
	179, 248, 181, 182, 183, 184, 185, 186,
	187, 188, 190, 191, 191, 191, 248, 193,
	194, 195, 196, 197, 198, 199, 200, 201,
	202, 203, 204, 249, 207, 208, 209, 210,
	211, 212, 213, 215, 216, 216, 216, 248,
	218, 219, 220, 221, 222, 223, 225, 226,
	226, 226, 248, 228, 229, 231, 232, 232,
	232, 248, 234, 235, 243, 236, 237, 238,
	239, 241, 242, 242, 242, 248, 244, 245,
	246, 248, 248, 249, 1, 0
};

static const signed char _cmd_cfg_cond_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 17,
	0, 1, 62, 0, 17, 0, 1, 59,
	0, 0, 17, 0, 1, 56, 0, 0,
	0, 17, 0, 1, 53, 0, 0, 0,
	0, 0, 0, 0, 17, 0, 1, 44,
	0, 0, 0, 0, 0, 0, 17, 0,
	1, 20, 0, 0, 0, 0, 17, 0,
	1, 77, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 9, 0, 0, 0, 0, 0, 0,
	0, 0, 17, 0, 1, 65, 0, 0,
	0, 13, 0, 0, 0, 0, 0, 0,
	17, 0, 1, 23, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 17, 0, 1,
	38, 0, 0, 0, 0, 0, 0, 0,
	17, 0, 1, 26, 0, 3, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 7, 0, 0, 0, 0, 17, 0,
	1, 29, 0, 0, 0, 0, 0, 0,
	0, 0, 17, 0, 1, 68, 0, 0,
	0, 0, 0, 0, 0, 0, 17, 0,
	1, 71, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 17, 0,
	1, 74, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 17, 0, 1, 50, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 5, 0, 0, 0, 0,
	0, 0, 0, 0, 17, 0, 1, 41,
	0, 0, 0, 0, 0, 0, 0, 17,
	0, 1, 47, 0, 0, 0, 17, 0,
	1, 35, 0, 0, 0, 0, 0, 0,
	0, 0, 17, 0, 1, 32, 0, 0,
	0, 11, 0, 15, 15, 0
};

static const short _cmd_cfg_eof_trans[] = {
	1, 2, 3, 30, 41, 42, 43, 44,
	45, 46, 47, 48, 49, 50, 53, 10,
	55, 57, 54, 22, 60, 62, 51, 65,
	16, 66, 68, 52, 71, 72, 29, 73,
	75, 31, 78, 81, 82, 83, 5, 84,
	86, 79, 89, 90, 91, 92, 93, 8,
	94, 96, 80, 99, 100, 101, 18, 102,
	104, 32, 107, 108, 109, 110, 111, 112,
	113, 114, 115, 116, 117, 118, 119, 120,
	121, 7, 33, 123, 124, 125, 126, 127,
	128, 129, 26, 130, 132, 34, 135, 137,
	4, 136, 139, 140, 141, 142, 143, 20,
	144, 146, 35, 149, 151, 152, 153, 154,
	155, 156, 14, 157, 159, 150, 162, 163,
	164, 165, 166, 167, 21, 168, 170, 36,
	173, 23, 37, 175, 177, 180, 181, 182,
	183, 184, 185, 186, 187, 188, 189, 190,
	191, 192, 193, 19, 178, 195, 196, 197,
	24, 198, 200, 179, 203, 204, 205, 206,
	207, 208, 209, 12, 210, 212, 176, 215,
	216, 217, 218, 219, 220, 221, 9, 222,
	224, 38, 227, 232, 233, 234, 235, 236,
	237, 11, 238, 240, 228, 243, 244, 245,
	246, 247, 248, 249, 250, 17, 251, 253,
	229, 256, 257, 258, 259, 260, 261, 262,
	263, 264, 265, 266, 267, 13, 230, 269,
	270, 271, 272, 273, 274, 275, 6, 276,
	278, 231, 281, 282, 283, 284, 285, 286,
	25, 287, 289, 39, 292, 293, 27, 294,
	296, 40, 299, 300, 302, 303, 304, 305,
	15, 306, 308, 301, 311, 312, 313, 28,
	315, 316, 0
};

static const int cmd_cfg_start = 248;
static const int cmd_cfg_first_final = 248;
static const int cmd_cfg_error = 0;

static const int cmd_cfg_en_main = 248;


#line 368 "cfg.rl"


void parse_cmdline(int argc, char *argv[])
{
	char argb[8192];
	size_t argbl = 0;
	for (size_t i = 1; i < (size_t)argc; ++i) {
		ssize_t snl;
		if (i > 1) snl = snprintf(argb + argbl, sizeof argb - argbl, "%c%s", 0, argv[i]);
			else snl = snprintf(argb + argbl, sizeof argb - argbl, "%s", argv[i]);
			if (snl < 0 || (size_t)snl > sizeof argb)
			suicide("error parsing command line option: option too long\n");
		argbl += (size_t)snl;
	}
	if (argbl == 0)
		return;
	struct cfgparse ccfg;
	memset(&ccfg, 0, sizeof ccfg);
	const char *p = argb;
	const char *pe = argb + argbl + 1;
	const char *eof = pe;
	

#line 1277 "cfg.c"
	{
		ccfg.cs = (int)cmd_cfg_start;
	}
	
#line 390 "cfg.rl"


#line 1282 "cfg.c"
	{
		unsigned int _trans = 0;
		const char * _keys;
		const signed char * _acts;
		const short * _inds;
		unsigned int _nacts;
		int _ic;
		_resume: {}
		if ( p == pe && p != eof )
			goto _out;
		if ( p == eof ) {
			if ( _cmd_cfg_eof_trans[ccfg.cs] > 0 ) {
				_trans = (unsigned int)_cmd_cfg_eof_trans[ccfg.cs] - 1;
			}
		}
		else {
			_keys = ( _cmd_cfg_trans_keys + ((ccfg.cs<<1)));
			_inds = ( _cmd_cfg_indices + (_cmd_cfg_index_offsets[ccfg.cs]));
			
			if ( ( (*( p))) <= 121 && ( (*( p))) >= 0 ) {
				_ic = (int)_cmd_cfg_char_class[(int)( (*( p))) - 0];
				if ( _ic <= (int)(*( _keys+1)) && _ic >= (int)(*( _keys)) )
					_trans = (unsigned int)(*( _inds + (int)( _ic - (int)(*( _keys)) ) )); 
				else
					_trans = (unsigned int)_cmd_cfg_index_defaults[ccfg.cs];
			}
			else {
				_trans = (unsigned int)_cmd_cfg_index_defaults[ccfg.cs];
			}
			
		}
		ccfg.cs = (int)_cmd_cfg_cond_targs[_trans];
		
		if ( _cmd_cfg_cond_actions[_trans] != 0 ) {
			
			_acts = ( _cmd_cfg_actions + (_cmd_cfg_cond_actions[_trans]));
			_nacts = (unsigned int)(*( _acts));
			_acts += 1;
			while ( _nacts > 0 ) {
				switch ( (*( _acts)) )
				{
					case 0:  {
							{
#line 76 "cfg.rl"
							
							memset(&ccfg.buf, 0, sizeof ccfg.buf);
							ccfg.buflen = 0;
							ccfg.ternary = 0;
						}
						
#line 1332 "cfg.c"

						break; 
					}
					case 1:  {
							{
#line 81 "cfg.rl"
							
							if (ccfg.buflen < sizeof ccfg.buf - 1)
							ccfg.buf[ccfg.buflen++] = *p;
							else
							suicide("line or option is too long\n");
						}
						
#line 1345 "cfg.c"

						break; 
					}
					case 2:  {
							{
#line 87 "cfg.rl"
							
							if (ccfg.buflen < sizeof ccfg.buf)
							ccfg.buf[ccfg.buflen] = 0;
						}
						
#line 1356 "cfg.c"

						break; 
					}
					case 3:  {
							{
#line 94 "cfg.rl"
							get_clientid_string(ccfg.buf, ccfg.buflen); }
						
#line 1364 "cfg.c"

						break; 
					}
					case 4:  {
							{
#line 95 "cfg.rl"
							
							copy_cmdarg(client_config.hostname, ccfg.buf,
							sizeof client_config.hostname, "hostname");
						}
						
#line 1375 "cfg.c"

						break; 
					}
					case 5:  {
							{
#line 99 "cfg.rl"
							
							copy_cmdarg(client_config.interface, ccfg.buf,
							sizeof client_config.interface, "interface");
						}
						
#line 1386 "cfg.c"

						break; 
					}
					case 6:  {
							{
#line 103 "cfg.rl"
							
							switch (ccfg.ternary) {
								case 1: client_config.abort_if_no_lease = true; break;
								case -1: client_config.abort_if_no_lease = false; default: break;
							}
						}
						
#line 1399 "cfg.c"

						break; 
					}
					case 7:  {
							{
#line 109 "cfg.rl"
							set_client_addr(ccfg.buf); }
						
#line 1407 "cfg.c"

						break; 
					}
					case 8:  {
							{
#line 110 "cfg.rl"
							
							copy_cmdarg(client_config.vendor, ccfg.buf,
							sizeof client_config.vendor, "vendorid");
						}
						
#line 1418 "cfg.c"

						break; 
					}
					case 9:  {
							{
#line 114 "cfg.rl"
							
							if (nk_uidgidbyname(ccfg.buf, &ndhc_uid, &ndhc_gid))
							suicide("invalid ndhc user '%s' specified\n", ccfg.buf);
						}
						
#line 1429 "cfg.c"

						break; 
					}
					case 10:  {
							{
#line 118 "cfg.rl"
							
							if (nk_uidgidbyname(ccfg.buf, &ifch_uid, &ifch_gid))
							suicide("invalid ifch user '%s' specified\n", ccfg.buf);
						}
						
#line 1440 "cfg.c"

						break; 
					}
					case 11:  {
							{
#line 122 "cfg.rl"
							
							if (nk_uidgidbyname(ccfg.buf, &sockd_uid, &sockd_gid))
							suicide("invalid sockd user '%s' specified\n", ccfg.buf);
						}
						
#line 1451 "cfg.c"

						break; 
					}
					case 12:  {
							{
#line 126 "cfg.rl"
							
							copy_cmdarg(chroot_dir, ccfg.buf, sizeof chroot_dir, "chroot");
						}
						
#line 1461 "cfg.c"

						break; 
					}
					case 13:  {
							{
#line 129 "cfg.rl"
							
							copy_cmdarg(state_dir, ccfg.buf, sizeof state_dir, "state-dir");
						}
						
#line 1471 "cfg.c"

						break; 
					}
					case 14:  {
							{
#line 132 "cfg.rl"
							
							copy_cmdarg(script_file, ccfg.buf, sizeof script_file, "script-file");
						}
						
#line 1481 "cfg.c"

						break; 
					}
					case 15:  {
							{
#line 135 "cfg.rl"
							
							log_line("seccomp_enforce option is deprecated; please remove it\n"
							"In the meanwhile, it is ignored and seccomp is disabled.\n");
						}
						
#line 1492 "cfg.c"

						break; 
					}
					case 16:  {
							{
#line 139 "cfg.rl"
							
							switch (ccfg.ternary) {
								case 1: set_arp_relentless_def(true); break;
								case -1: set_arp_relentless_def(false); default: break;
							}
						}
						
#line 1505 "cfg.c"

						break; 
					}
					case 17:  {
							{
#line 145 "cfg.rl"
							
							int t = atoi(ccfg.buf);
							if (t >= 0)
							arp_probe_wait = (unsigned)t;
						}
						
#line 1517 "cfg.c"

						break; 
					}
					case 18:  {
							{
#line 150 "cfg.rl"
							
							int t = atoi(ccfg.buf);
							if (t >= 0)
							arp_probe_num = (unsigned)t;
						}
						
#line 1529 "cfg.c"

						break; 
					}
					case 19:  {
							{
#line 155 "cfg.rl"
							
							int ti = atoi(ccfg.buf);
							if (ti >= 0) {
								unsigned t = (unsigned)ti;
								arp_probe_min = t;
								if (arp_probe_min > arp_probe_max) {
									t = arp_probe_max;
									arp_probe_max = arp_probe_min;
									arp_probe_min = t;
								}
							}
						}
						
#line 1548 "cfg.c"

						break; 
					}
					case 20:  {
							{
#line 167 "cfg.rl"
							
							int ti = atoi(ccfg.buf);
							if (ti >= 0) {
								unsigned t = (unsigned)ti;
								arp_probe_max = t;
								if (arp_probe_min > arp_probe_max) {
									t = arp_probe_max;
									arp_probe_max = arp_probe_min;
									arp_probe_min = t;
								}
							}
						}
						
#line 1567 "cfg.c"

						break; 
					}
					case 21:  {
							{
#line 179 "cfg.rl"
							
							char *q;
							long mt = strtol(ccfg.buf, &q, 10);
							if (q == ccfg.buf)
							suicide("gw-metric arg '%s' isn't a valid number\n", ccfg.buf);
							if (mt > INT_MAX)
							suicide("gw-metric arg '%s' is too large\n", ccfg.buf);
							if (mt < 0)
							mt = 0;
							client_config.metric = (int)mt;
						}
						
#line 1585 "cfg.c"

						break; 
					}
					case 22:  {
							{
#line 190 "cfg.rl"
							
							copy_cmdarg(resolv_conf_d, ccfg.buf, sizeof resolv_conf_d,
							"resolv-conf");
						}
						
#line 1596 "cfg.c"

						break; 
					}
					case 23:  {
							{
#line 194 "cfg.rl"
							
							switch (ccfg.ternary) {
								case 1: allow_hostname = 1; break;
								case -1: allow_hostname = 0; default: break;
							}
						}
						
#line 1609 "cfg.c"

						break; 
					}
					case 24:  {
							{
#line 200 "cfg.rl"
							
							uint32_t t = (uint32_t)atoi(ccfg.buf);
							client_config.rfkillIdx = t;
							client_config.enable_rfkill = true;
						}
						
#line 1621 "cfg.c"

						break; 
					}
					case 25:  {
							{
#line 205 "cfg.rl"
							
							client_config.s6_notify_fd = atoi(ccfg.buf);
							client_config.enable_s6_notify = true;
						}
						
#line 1632 "cfg.c"

						break; 
					}
					case 26:  {
							{
#line 209 "cfg.rl"
							print_version(); exit(EXIT_SUCCESS); }
						
#line 1640 "cfg.c"

						break; 
					}
					case 27:  {
							{
#line 210 "cfg.rl"
							show_usage(); exit(EXIT_SUCCESS); }
						
#line 1648 "cfg.c"

						break; 
					}
					case 28:  {
							{
#line 325 "cfg.rl"
							parse_cfgfile(ccfg.buf); }
						
#line 1656 "cfg.c"

						break; 
					}
					case 29:  {
							{
#line 326 "cfg.rl"
							ccfg.ternary = 1; }
						
#line 1664 "cfg.c"

						break; 
					}
				}
				_nacts -= 1;
				_acts += 1;
			}
			
		}
		
		if ( p == eof ) {
			if ( ccfg.cs >= 248 )
				goto _out;
		}
		else {
			if ( ccfg.cs != 0 ) {
				p += 1;
				goto _resume;
			}
		}
		_out: {}
	}
	
#line 391 "cfg.rl"

	
	if (ccfg.cs == cmd_cfg_error)
		suicide("error parsing command line option: malformed\n");
	if (ccfg.cs >= cmd_cfg_first_final)
		return;
	suicide("error parsing command line option: incomplete\n");
}

