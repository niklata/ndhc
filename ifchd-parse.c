#line 1 "ifchd-parse.rl"
// Copyright 2004-2018 Nicholas J. Kain <njkain at gmail dot com>
// SPDX-License-Identifier: MIT
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "nk/log.h"
#include "ifchd-parse.h"
#include "ifchd.h"
#include "ifset.h"
#include "ndhc.h"


#line 48 "ifchd-parse.rl"



#line 18 "ifchd-parse.c"
static const int ipv4set_parser_start = 1;
static const int ipv4set_parser_first_final = 43;
static const int ipv4set_parser_error = 0;

static const int ipv4set_parser_en_main = 1;


#line 50 "ifchd-parse.rl"


static int perform_ip4set(const char *buf, size_t len)
{
	char ip4_addr[INET_ADDRSTRLEN];
	char ip4_subnet[INET_ADDRSTRLEN];
	char ip4_bcast[INET_ADDRSTRLEN];
	const char *p = buf;
	const char *pe = p + len;
	const char *eof = pe;
	const char *arg_start = p;
	int cs = 0;
	bool have_ip = false;
	bool have_subnet = false;
	bool have_bcast = false;
	

#line 41 "ifchd-parse.c"
	{
		cs = (int)ipv4set_parser_start;
	}
	
#line 66 "ifchd-parse.rl"


#line 46 "ifchd-parse.c"
{
		switch ( cs ) {
			case 1:
			goto st_case_1;
			case 0:
			goto st_case_0;
			case 2:
			goto st_case_2;
			case 3:
			goto st_case_3;
			case 4:
			goto st_case_4;
			case 5:
			goto st_case_5;
			case 6:
			goto st_case_6;
			case 7:
			goto st_case_7;
			case 8:
			goto st_case_8;
			case 9:
			goto st_case_9;
			case 10:
			goto st_case_10;
			case 11:
			goto st_case_11;
			case 12:
			goto st_case_12;
			case 13:
			goto st_case_13;
			case 14:
			goto st_case_14;
			case 15:
			goto st_case_15;
			case 43:
			goto st_case_43;
			case 16:
			goto st_case_16;
			case 17:
			goto st_case_17;
			case 18:
			goto st_case_18;
			case 19:
			goto st_case_19;
			case 20:
			goto st_case_20;
			case 21:
			goto st_case_21;
			case 22:
			goto st_case_22;
			case 44:
			goto st_case_44;
			case 45:
			goto st_case_45;
			case 46:
			goto st_case_46;
			case 23:
			goto st_case_23;
			case 24:
			goto st_case_24;
			case 25:
			goto st_case_25;
			case 26:
			goto st_case_26;
			case 27:
			goto st_case_27;
			case 28:
			goto st_case_28;
			case 47:
			goto st_case_47;
			case 48:
			goto st_case_48;
			case 29:
			goto st_case_29;
			case 30:
			goto st_case_30;
			case 31:
			goto st_case_31;
			case 32:
			goto st_case_32;
			case 33:
			goto st_case_33;
			case 34:
			goto st_case_34;
			case 35:
			goto st_case_35;
			case 36:
			goto st_case_36;
			case 37:
			goto st_case_37;
			case 38:
			goto st_case_38;
			case 39:
			goto st_case_39;
			case 40:
			goto st_case_40;
			case 41:
			goto st_case_41;
			case 42:
			goto st_case_42;
		}
		_st1:
		if ( p == eof )
			goto _out1;
		p+= 1;
		st_case_1:
		if ( p == pe && p != eof )
			goto _out1;
		if ( p == eof ) {
			goto _st1;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _ctr2;
			}
			goto _st0;
		}
		_st0:
		if ( p == eof )
			goto _out0;
		st_case_0:
		goto _out0;
		_ctr2:
			{
#line 17 "ifchd-parse.rl"
			arg_start = p; }
		
#line 172 "ifchd-parse.c"

		goto _st2;
		_st2:
		if ( p == eof )
			goto _out2;
		p+= 1;
		st_case_2:
		if ( p == pe && p != eof )
			goto _out2;
		if ( p == eof ) {
			goto _st2;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st3;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st41;
			}
			goto _st0;
		}
		_st3:
		if ( p == eof )
			goto _out3;
		p+= 1;
		st_case_3:
		if ( p == pe && p != eof )
			goto _out3;
		if ( p == eof ) {
			goto _st3;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st4;
			}
			goto _st0;
		}
		_st4:
		if ( p == eof )
			goto _out4;
		p+= 1;
		st_case_4:
		if ( p == pe && p != eof )
			goto _out4;
		if ( p == eof ) {
			goto _st4;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st5;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st39;
			}
			goto _st0;
		}
		_st5:
		if ( p == eof )
			goto _out5;
		p+= 1;
		st_case_5:
		if ( p == pe && p != eof )
			goto _out5;
		if ( p == eof ) {
			goto _st5;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st6;
			}
			goto _st0;
		}
		_st6:
		if ( p == eof )
			goto _out6;
		p+= 1;
		st_case_6:
		if ( p == pe && p != eof )
			goto _out6;
		if ( p == eof ) {
			goto _st6;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st7;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st37;
			}
			goto _st0;
		}
		_st7:
		if ( p == eof )
			goto _out7;
		p+= 1;
		st_case_7:
		if ( p == pe && p != eof )
			goto _out7;
		if ( p == eof ) {
			goto _st7;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st8;
			}
			goto _st0;
		}
		_st8:
		if ( p == eof )
			goto _out8;
		p+= 1;
		st_case_8:
		if ( p == pe && p != eof )
			goto _out8;
		if ( p == eof ) {
			goto _st8;}
		else {
			if ( ( (*( p))) == 44 ) {
				goto _ctr13;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st35;
			}
			goto _st0;
		}
		_ctr13:
			{
#line 18 "ifchd-parse.rl"
			
			ptrdiff_t arg_len = p - arg_start;
			if (arg_len > 0 && (size_t)arg_len < sizeof ip4_addr) {
				have_ip = true;
				memcpy(ip4_addr, arg_start, (size_t)arg_len);
			}
			ip4_addr[arg_len] = 0;
		}
		
#line 303 "ifchd-parse.c"

		goto _st9;
		_st9:
		if ( p == eof )
			goto _out9;
		p+= 1;
		st_case_9:
		if ( p == pe && p != eof )
			goto _out9;
		if ( p == eof ) {
			goto _st9;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _ctr16;
			}
			goto _st0;
		}
		_ctr16:
			{
#line 17 "ifchd-parse.rl"
			arg_start = p; }
		
#line 325 "ifchd-parse.c"

		goto _st10;
		_st10:
		if ( p == eof )
			goto _out10;
		p+= 1;
		st_case_10:
		if ( p == pe && p != eof )
			goto _out10;
		if ( p == eof ) {
			goto _st10;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st11;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st33;
			}
			goto _st0;
		}
		_st11:
		if ( p == eof )
			goto _out11;
		p+= 1;
		st_case_11:
		if ( p == pe && p != eof )
			goto _out11;
		if ( p == eof ) {
			goto _st11;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st12;
			}
			goto _st0;
		}
		_st12:
		if ( p == eof )
			goto _out12;
		p+= 1;
		st_case_12:
		if ( p == pe && p != eof )
			goto _out12;
		if ( p == eof ) {
			goto _st12;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st13;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st31;
			}
			goto _st0;
		}
		_st13:
		if ( p == eof )
			goto _out13;
		p+= 1;
		st_case_13:
		if ( p == pe && p != eof )
			goto _out13;
		if ( p == eof ) {
			goto _st13;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st14;
			}
			goto _st0;
		}
		_st14:
		if ( p == eof )
			goto _out14;
		p+= 1;
		st_case_14:
		if ( p == pe && p != eof )
			goto _out14;
		if ( p == eof ) {
			goto _st14;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st15;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st29;
			}
			goto _st0;
		}
		_st15:
		if ( p == eof )
			goto _out15;
		p+= 1;
		st_case_15:
		if ( p == pe && p != eof )
			goto _out15;
		if ( p == eof ) {
			goto _st15;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st43;
			}
			goto _st0;
		}
		_ctr49:
			{
#line 26 "ifchd-parse.rl"
			
			ptrdiff_t arg_len = p - arg_start;
			if (arg_len > 0 && (size_t)arg_len < sizeof ip4_subnet) {
				have_subnet = true;
				memcpy(ip4_subnet, arg_start, (size_t)arg_len);
			}
			ip4_subnet[arg_len] = 0;
		}
		
#line 438 "ifchd-parse.c"

		goto _st43;
		_st43:
		if ( p == eof )
			goto _out43;
		p+= 1;
		st_case_43:
		if ( p == pe && p != eof )
			goto _out43;
		if ( p == eof ) {
			goto _ctr49;}
		else {
			if ( ( (*( p))) == 44 ) {
				goto _ctr50;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st47;
			}
			goto _st0;
		}
		_ctr50:
			{
#line 26 "ifchd-parse.rl"
			
			ptrdiff_t arg_len = p - arg_start;
			if (arg_len > 0 && (size_t)arg_len < sizeof ip4_subnet) {
				have_subnet = true;
				memcpy(ip4_subnet, arg_start, (size_t)arg_len);
			}
			ip4_subnet[arg_len] = 0;
		}
		
#line 470 "ifchd-parse.c"

		goto _st16;
		_st16:
		if ( p == eof )
			goto _out16;
		p+= 1;
		st_case_16:
		if ( p == pe && p != eof )
			goto _out16;
		if ( p == eof ) {
			goto _st16;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _ctr28;
			}
			goto _st0;
		}
		_ctr28:
			{
#line 17 "ifchd-parse.rl"
			arg_start = p; }
		
#line 492 "ifchd-parse.c"

		goto _st17;
		_st17:
		if ( p == eof )
			goto _out17;
		p+= 1;
		st_case_17:
		if ( p == pe && p != eof )
			goto _out17;
		if ( p == eof ) {
			goto _st17;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st18;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st27;
			}
			goto _st0;
		}
		_st18:
		if ( p == eof )
			goto _out18;
		p+= 1;
		st_case_18:
		if ( p == pe && p != eof )
			goto _out18;
		if ( p == eof ) {
			goto _st18;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st19;
			}
			goto _st0;
		}
		_st19:
		if ( p == eof )
			goto _out19;
		p+= 1;
		st_case_19:
		if ( p == pe && p != eof )
			goto _out19;
		if ( p == eof ) {
			goto _st19;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st20;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st25;
			}
			goto _st0;
		}
		_st20:
		if ( p == eof )
			goto _out20;
		p+= 1;
		st_case_20:
		if ( p == pe && p != eof )
			goto _out20;
		if ( p == eof ) {
			goto _st20;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st21;
			}
			goto _st0;
		}
		_st21:
		if ( p == eof )
			goto _out21;
		p+= 1;
		st_case_21:
		if ( p == pe && p != eof )
			goto _out21;
		if ( p == eof ) {
			goto _st21;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st22;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st23;
			}
			goto _st0;
		}
		_st22:
		if ( p == eof )
			goto _out22;
		p+= 1;
		st_case_22:
		if ( p == pe && p != eof )
			goto _out22;
		if ( p == eof ) {
			goto _st22;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st44;
			}
			goto _st0;
		}
		_ctr52:
			{
#line 34 "ifchd-parse.rl"
			
			ptrdiff_t arg_len = p - arg_start;
			if (arg_len > 0 && (size_t)arg_len < sizeof ip4_bcast) {
				have_ip = true;
				memcpy(ip4_bcast, arg_start, (size_t)arg_len);
			}
			ip4_bcast[arg_len] = 0;
		}
		
#line 605 "ifchd-parse.c"

		goto _st44;
		_st44:
		if ( p == eof )
			goto _out44;
		p+= 1;
		st_case_44:
		if ( p == pe && p != eof )
			goto _out44;
		if ( p == eof ) {
			goto _ctr52;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st45;
			}
			goto _st0;
		}
		_ctr54:
			{
#line 34 "ifchd-parse.rl"
			
			ptrdiff_t arg_len = p - arg_start;
			if (arg_len > 0 && (size_t)arg_len < sizeof ip4_bcast) {
				have_ip = true;
				memcpy(ip4_bcast, arg_start, (size_t)arg_len);
			}
			ip4_bcast[arg_len] = 0;
		}
		
#line 634 "ifchd-parse.c"

		goto _st45;
		_st45:
		if ( p == eof )
			goto _out45;
		p+= 1;
		st_case_45:
		if ( p == pe && p != eof )
			goto _out45;
		if ( p == eof ) {
			goto _ctr54;}
		else {
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st46;
			}
			goto _st0;
		}
		_ctr56:
			{
#line 34 "ifchd-parse.rl"
			
			ptrdiff_t arg_len = p - arg_start;
			if (arg_len > 0 && (size_t)arg_len < sizeof ip4_bcast) {
				have_ip = true;
				memcpy(ip4_bcast, arg_start, (size_t)arg_len);
			}
			ip4_bcast[arg_len] = 0;
		}
		
#line 663 "ifchd-parse.c"

		goto _st46;
		_st46:
		if ( p == eof )
			goto _out46;
		p+= 1;
		st_case_46:
		if ( p == pe && p != eof )
			goto _out46;
		if ( p == eof ) {
			goto _ctr56;}
		else {
			goto _st0;
		}
		_st23:
		if ( p == eof )
			goto _out23;
		p+= 1;
		st_case_23:
		if ( p == pe && p != eof )
			goto _out23;
		if ( p == eof ) {
			goto _st23;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st22;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st24;
			}
			goto _st0;
		}
		_st24:
		if ( p == eof )
			goto _out24;
		p+= 1;
		st_case_24:
		if ( p == pe && p != eof )
			goto _out24;
		if ( p == eof ) {
			goto _st24;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st22;
			}
			goto _st0;
		}
		_st25:
		if ( p == eof )
			goto _out25;
		p+= 1;
		st_case_25:
		if ( p == pe && p != eof )
			goto _out25;
		if ( p == eof ) {
			goto _st25;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st20;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st26;
			}
			goto _st0;
		}
		_st26:
		if ( p == eof )
			goto _out26;
		p+= 1;
		st_case_26:
		if ( p == pe && p != eof )
			goto _out26;
		if ( p == eof ) {
			goto _st26;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st20;
			}
			goto _st0;
		}
		_st27:
		if ( p == eof )
			goto _out27;
		p+= 1;
		st_case_27:
		if ( p == pe && p != eof )
			goto _out27;
		if ( p == eof ) {
			goto _st27;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st18;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st28;
			}
			goto _st0;
		}
		_st28:
		if ( p == eof )
			goto _out28;
		p+= 1;
		st_case_28:
		if ( p == pe && p != eof )
			goto _out28;
		if ( p == eof ) {
			goto _st28;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st18;
			}
			goto _st0;
		}
		_ctr57:
			{
#line 26 "ifchd-parse.rl"
			
			ptrdiff_t arg_len = p - arg_start;
			if (arg_len > 0 && (size_t)arg_len < sizeof ip4_subnet) {
				have_subnet = true;
				memcpy(ip4_subnet, arg_start, (size_t)arg_len);
			}
			ip4_subnet[arg_len] = 0;
		}
		
#line 788 "ifchd-parse.c"

		goto _st47;
		_st47:
		if ( p == eof )
			goto _out47;
		p+= 1;
		st_case_47:
		if ( p == pe && p != eof )
			goto _out47;
		if ( p == eof ) {
			goto _ctr57;}
		else {
			if ( ( (*( p))) == 44 ) {
				goto _ctr50;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st48;
			}
			goto _st0;
		}
		_ctr59:
			{
#line 26 "ifchd-parse.rl"
			
			ptrdiff_t arg_len = p - arg_start;
			if (arg_len > 0 && (size_t)arg_len < sizeof ip4_subnet) {
				have_subnet = true;
				memcpy(ip4_subnet, arg_start, (size_t)arg_len);
			}
			ip4_subnet[arg_len] = 0;
		}
		
#line 820 "ifchd-parse.c"

		goto _st48;
		_st48:
		if ( p == eof )
			goto _out48;
		p+= 1;
		st_case_48:
		if ( p == pe && p != eof )
			goto _out48;
		if ( p == eof ) {
			goto _ctr59;}
		else {
			if ( ( (*( p))) == 44 ) {
				goto _ctr50;
			}
			goto _st0;
		}
		_st29:
		if ( p == eof )
			goto _out29;
		p+= 1;
		st_case_29:
		if ( p == pe && p != eof )
			goto _out29;
		if ( p == eof ) {
			goto _st29;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st15;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st30;
			}
			goto _st0;
		}
		_st30:
		if ( p == eof )
			goto _out30;
		p+= 1;
		st_case_30:
		if ( p == pe && p != eof )
			goto _out30;
		if ( p == eof ) {
			goto _st30;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st15;
			}
			goto _st0;
		}
		_st31:
		if ( p == eof )
			goto _out31;
		p+= 1;
		st_case_31:
		if ( p == pe && p != eof )
			goto _out31;
		if ( p == eof ) {
			goto _st31;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st13;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st32;
			}
			goto _st0;
		}
		_st32:
		if ( p == eof )
			goto _out32;
		p+= 1;
		st_case_32:
		if ( p == pe && p != eof )
			goto _out32;
		if ( p == eof ) {
			goto _st32;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st13;
			}
			goto _st0;
		}
		_st33:
		if ( p == eof )
			goto _out33;
		p+= 1;
		st_case_33:
		if ( p == pe && p != eof )
			goto _out33;
		if ( p == eof ) {
			goto _st33;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st11;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st34;
			}
			goto _st0;
		}
		_st34:
		if ( p == eof )
			goto _out34;
		p+= 1;
		st_case_34:
		if ( p == pe && p != eof )
			goto _out34;
		if ( p == eof ) {
			goto _st34;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st11;
			}
			goto _st0;
		}
		_st35:
		if ( p == eof )
			goto _out35;
		p+= 1;
		st_case_35:
		if ( p == pe && p != eof )
			goto _out35;
		if ( p == eof ) {
			goto _st35;}
		else {
			if ( ( (*( p))) == 44 ) {
				goto _ctr13;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st36;
			}
			goto _st0;
		}
		_st36:
		if ( p == eof )
			goto _out36;
		p+= 1;
		st_case_36:
		if ( p == pe && p != eof )
			goto _out36;
		if ( p == eof ) {
			goto _st36;}
		else {
			if ( ( (*( p))) == 44 ) {
				goto _ctr13;
			}
			goto _st0;
		}
		_st37:
		if ( p == eof )
			goto _out37;
		p+= 1;
		st_case_37:
		if ( p == pe && p != eof )
			goto _out37;
		if ( p == eof ) {
			goto _st37;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st7;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st38;
			}
			goto _st0;
		}
		_st38:
		if ( p == eof )
			goto _out38;
		p+= 1;
		st_case_38:
		if ( p == pe && p != eof )
			goto _out38;
		if ( p == eof ) {
			goto _st38;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st7;
			}
			goto _st0;
		}
		_st39:
		if ( p == eof )
			goto _out39;
		p+= 1;
		st_case_39:
		if ( p == pe && p != eof )
			goto _out39;
		if ( p == eof ) {
			goto _st39;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st5;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st40;
			}
			goto _st0;
		}
		_st40:
		if ( p == eof )
			goto _out40;
		p+= 1;
		st_case_40:
		if ( p == pe && p != eof )
			goto _out40;
		if ( p == eof ) {
			goto _st40;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st5;
			}
			goto _st0;
		}
		_st41:
		if ( p == eof )
			goto _out41;
		p+= 1;
		st_case_41:
		if ( p == pe && p != eof )
			goto _out41;
		if ( p == eof ) {
			goto _st41;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st3;
			}
			if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
				goto _st42;
			}
			goto _st0;
		}
		_st42:
		if ( p == eof )
			goto _out42;
		p+= 1;
		st_case_42:
		if ( p == pe && p != eof )
			goto _out42;
		if ( p == eof ) {
			goto _st42;}
		else {
			if ( ( (*( p))) == 46 ) {
				goto _st3;
			}
			goto _st0;
		}
		_out1: cs = 1; goto _out; 
		_out0: cs = 0; goto _out; 
		_out2: cs = 2; goto _out; 
		_out3: cs = 3; goto _out; 
		_out4: cs = 4; goto _out; 
		_out5: cs = 5; goto _out; 
		_out6: cs = 6; goto _out; 
		_out7: cs = 7; goto _out; 
		_out8: cs = 8; goto _out; 
		_out9: cs = 9; goto _out; 
		_out10: cs = 10; goto _out; 
		_out11: cs = 11; goto _out; 
		_out12: cs = 12; goto _out; 
		_out13: cs = 13; goto _out; 
		_out14: cs = 14; goto _out; 
		_out15: cs = 15; goto _out; 
		_out43: cs = 43; goto _out; 
		_out16: cs = 16; goto _out; 
		_out17: cs = 17; goto _out; 
		_out18: cs = 18; goto _out; 
		_out19: cs = 19; goto _out; 
		_out20: cs = 20; goto _out; 
		_out21: cs = 21; goto _out; 
		_out22: cs = 22; goto _out; 
		_out44: cs = 44; goto _out; 
		_out45: cs = 45; goto _out; 
		_out46: cs = 46; goto _out; 
		_out23: cs = 23; goto _out; 
		_out24: cs = 24; goto _out; 
		_out25: cs = 25; goto _out; 
		_out26: cs = 26; goto _out; 
		_out27: cs = 27; goto _out; 
		_out28: cs = 28; goto _out; 
		_out47: cs = 47; goto _out; 
		_out48: cs = 48; goto _out; 
		_out29: cs = 29; goto _out; 
		_out30: cs = 30; goto _out; 
		_out31: cs = 31; goto _out; 
		_out32: cs = 32; goto _out; 
		_out33: cs = 33; goto _out; 
		_out34: cs = 34; goto _out; 
		_out35: cs = 35; goto _out; 
		_out36: cs = 36; goto _out; 
		_out37: cs = 37; goto _out; 
		_out38: cs = 38; goto _out; 
		_out39: cs = 39; goto _out; 
		_out40: cs = 40; goto _out; 
		_out41: cs = 41; goto _out; 
		_out42: cs = 42; goto _out; 
		_out: {}
	}
	
#line 67 "ifchd-parse.rl"

	
	if (cs < ipv4set_parser_first_final) {
		log_line("%s: received invalid arguments\n", __func__);
		return -1;
	}
	
	// These should never trigger because of the above check, but be safe...
	if (!have_ip) {
		log_line("%s: No IPv4 address specified.\n", __func__);
		return -1;
	}
	if (!have_subnet) {
		log_line("%s: No IPv4 subnet specified.\n", __func__);
		return -1;
	}
	
	return perform_ip_subnet_bcast(ip4_addr, ip4_subnet,
	have_bcast ? ip4_bcast : (char *)0);
}


#line 158 "ifchd-parse.rl"



#line 1144 "ifchd-parse.c"
static const int ifchd_parser_start = 1;
static const int ifchd_parser_first_final = 126;
static const int ifchd_parser_error = 0;

static const int ifchd_parser_en_main = 1;


#line 160 "ifchd-parse.rl"


/*
* Returns -99 on fatal error; that leads to peer connection being closed.
* Returns -1 if one of the commands failed.
* Returns 0 on success.
*/
int execute_buffer(const char *newbuf)
{
	char buf[MAX_BUF * 2];
	char tb[MAX_BUF];
	int cmdf = 0;
	
	char *snp = memccpy(buf, cl.ibuf, 0, sizeof buf);
	memset(cl.ibuf, 0, sizeof cl.ibuf);
	if (!snp) {
		log_line("%s: (%s) memccpy failed\n", client_config.interface, __func__);
		return -99;
	}
	if (!memccpy(snp - 1, newbuf, 0, sizeof buf - (size_t)(snp - buf - 1))) {
		log_line("%s: (%s) memccpy failed\n", client_config.interface, __func__);
		return -99;
	}
	
	const char *p = buf;
	const char *pe = p + strlen(buf);
	const char *arg_start = p;
	const char *cmd_start = p;
	size_t arg_len = 0;
	int cs = 0;
	

#line 1182 "ifchd-parse.c"
	{
		cs = (int)ifchd_parser_start;
	}
	
#line 191 "ifchd-parse.rl"


#line 1187 "ifchd-parse.c"
{
		switch ( cs ) {
			case 1:
			goto st_case_1;
			case 0:
			goto st_case_0;
			case 2:
			goto st_case_2;
			case 3:
			goto st_case_3;
			case 4:
			goto st_case_4;
			case 5:
			goto st_case_5;
			case 6:
			goto st_case_6;
			case 7:
			goto st_case_7;
			case 8:
			goto st_case_8;
			case 9:
			goto st_case_9;
			case 126:
			goto st_case_126;
			case 10:
			goto st_case_10;
			case 11:
			goto st_case_11;
			case 12:
			goto st_case_12;
			case 13:
			goto st_case_13;
			case 14:
			goto st_case_14;
			case 15:
			goto st_case_15;
			case 16:
			goto st_case_16;
			case 17:
			goto st_case_17;
			case 18:
			goto st_case_18;
			case 19:
			goto st_case_19;
			case 20:
			goto st_case_20;
			case 21:
			goto st_case_21;
			case 22:
			goto st_case_22;
			case 23:
			goto st_case_23;
			case 24:
			goto st_case_24;
			case 25:
			goto st_case_25;
			case 26:
			goto st_case_26;
			case 27:
			goto st_case_27;
			case 28:
			goto st_case_28;
			case 29:
			goto st_case_29;
			case 30:
			goto st_case_30;
			case 31:
			goto st_case_31;
			case 32:
			goto st_case_32;
			case 33:
			goto st_case_33;
			case 34:
			goto st_case_34;
			case 35:
			goto st_case_35;
			case 36:
			goto st_case_36;
			case 37:
			goto st_case_37;
			case 38:
			goto st_case_38;
			case 39:
			goto st_case_39;
			case 40:
			goto st_case_40;
			case 41:
			goto st_case_41;
			case 42:
			goto st_case_42;
			case 43:
			goto st_case_43;
			case 44:
			goto st_case_44;
			case 45:
			goto st_case_45;
			case 46:
			goto st_case_46;
			case 47:
			goto st_case_47;
			case 48:
			goto st_case_48;
			case 49:
			goto st_case_49;
			case 50:
			goto st_case_50;
			case 51:
			goto st_case_51;
			case 52:
			goto st_case_52;
			case 53:
			goto st_case_53;
			case 54:
			goto st_case_54;
			case 55:
			goto st_case_55;
			case 56:
			goto st_case_56;
			case 57:
			goto st_case_57;
			case 58:
			goto st_case_58;
			case 59:
			goto st_case_59;
			case 60:
			goto st_case_60;
			case 61:
			goto st_case_61;
			case 62:
			goto st_case_62;
			case 63:
			goto st_case_63;
			case 64:
			goto st_case_64;
			case 65:
			goto st_case_65;
			case 66:
			goto st_case_66;
			case 67:
			goto st_case_67;
			case 68:
			goto st_case_68;
			case 69:
			goto st_case_69;
			case 70:
			goto st_case_70;
			case 71:
			goto st_case_71;
			case 72:
			goto st_case_72;
			case 73:
			goto st_case_73;
			case 74:
			goto st_case_74;
			case 75:
			goto st_case_75;
			case 76:
			goto st_case_76;
			case 77:
			goto st_case_77;
			case 78:
			goto st_case_78;
			case 79:
			goto st_case_79;
			case 80:
			goto st_case_80;
			case 81:
			goto st_case_81;
			case 82:
			goto st_case_82;
			case 83:
			goto st_case_83;
			case 84:
			goto st_case_84;
			case 85:
			goto st_case_85;
			case 86:
			goto st_case_86;
			case 87:
			goto st_case_87;
			case 88:
			goto st_case_88;
			case 89:
			goto st_case_89;
			case 90:
			goto st_case_90;
			case 91:
			goto st_case_91;
			case 92:
			goto st_case_92;
			case 93:
			goto st_case_93;
			case 94:
			goto st_case_94;
			case 95:
			goto st_case_95;
			case 96:
			goto st_case_96;
			case 97:
			goto st_case_97;
			case 98:
			goto st_case_98;
			case 99:
			goto st_case_99;
			case 100:
			goto st_case_100;
			case 101:
			goto st_case_101;
			case 102:
			goto st_case_102;
			case 103:
			goto st_case_103;
			case 104:
			goto st_case_104;
			case 105:
			goto st_case_105;
			case 106:
			goto st_case_106;
			case 107:
			goto st_case_107;
			case 108:
			goto st_case_108;
			case 109:
			goto st_case_109;
			case 110:
			goto st_case_110;
			case 111:
			goto st_case_111;
			case 112:
			goto st_case_112;
			case 113:
			goto st_case_113;
			case 114:
			goto st_case_114;
			case 115:
			goto st_case_115;
			case 116:
			goto st_case_116;
			case 117:
			goto st_case_117;
			case 118:
			goto st_case_118;
			case 119:
			goto st_case_119;
			case 120:
			goto st_case_120;
			case 121:
			goto st_case_121;
			case 122:
			goto st_case_122;
			case 123:
			goto st_case_123;
			case 124:
			goto st_case_124;
			case 125:
			goto st_case_125;
		}
		p+= 1;
		st_case_1:
		if ( p == pe )
			goto _out1;
		switch( ( (*( p))) ) {
			case 99: {
				goto _ctr2;
			}
			case 100: {
				goto _ctr3;
			}
			case 104: {
				goto _ctr4;
			}
			case 105: {
				goto _ctr5;
			}
			case 108: {
				goto _ctr6;
			}
			case 109: {
				goto _ctr7;
			}
			case 110: {
				goto _ctr8;
			}
			case 114: {
				goto _ctr9;
			}
			case 116: {
				goto _ctr10;
			}
			case 119: {
				goto _ctr11;
			}
		}
		goto _st0;
		_st0:
		st_case_0:
		goto _out0;
		_ctr2:
			{
#line 91 "ifchd-parse.rl"
			cl.state = STATE_NOTHING; }
		
#line 1489 "ifchd-parse.c"

		goto _st2;
		_st2:
		p+= 1;
		st_case_2:
		if ( p == pe )
			goto _out2;
		if ( ( (*( p))) == 97 ) {
			goto _st3;
		}
		goto _st0;
		_st3:
		p+= 1;
		st_case_3:
		if ( p == pe )
			goto _out3;
		if ( ( (*( p))) == 114 ) {
			goto _st4;
		}
		goto _st0;
		_st4:
		p+= 1;
		st_case_4:
		if ( p == pe )
			goto _out4;
		if ( ( (*( p))) == 114 ) {
			goto _st5;
		}
		goto _st0;
		_st5:
		p+= 1;
		st_case_5:
		if ( p == pe )
			goto _out5;
		if ( ( (*( p))) == 105 ) {
			goto _st6;
		}
		goto _st0;
		_st6:
		p+= 1;
		st_case_6:
		if ( p == pe )
			goto _out6;
		if ( ( (*( p))) == 101 ) {
			goto _st7;
		}
		goto _st0;
		_st7:
		p+= 1;
		st_case_7:
		if ( p == pe )
			goto _out7;
		if ( ( (*( p))) == 114 ) {
			goto _st8;
		}
		goto _st0;
		_st8:
		p+= 1;
		st_case_8:
		if ( p == pe )
			goto _out8;
		if ( ( (*( p))) == 58 ) {
			goto _st9;
		}
		goto _st0;
		_st9:
		p+= 1;
		st_case_9:
		if ( p == pe )
			goto _out9;
		if ( ( (*( p))) == 59 ) {
			goto _ctr20;
		}
		goto _st0;
		_ctr20:
			{
#line 154 "ifchd-parse.rl"
			cl.state = STATE_CARRIER; }
		
#line 1568 "ifchd-parse.c"

			{
#line 104 "ifchd-parse.rl"
			
			int pr = 0;
			cmd_start = p + 1;
			switch (cl.state) {
				case STATE_IP4SET: pr = perform_ip4set(tb, arg_len); break;
				case STATE_TIMEZONE: pr = perform_timezone( tb, arg_len); break;
				case STATE_ROUTER: pr = perform_router(tb, arg_len); break;
				case STATE_DNS: pr = perform_dns(tb, arg_len); break;
				case STATE_LPRSVR: pr = perform_lprsvr(tb, arg_len); break;
				case STATE_HOSTNAME: pr = perform_hostname(tb, arg_len); break;
				case STATE_DOMAIN: pr = perform_domain(tb, arg_len); break;
				case STATE_IPTTL: pr = perform_ipttl(tb, arg_len); break;
				case STATE_MTU: pr = perform_mtu(tb, arg_len); break;
				case STATE_NTPSVR: pr = perform_ntpsrv(tb, arg_len); break;
				case STATE_WINS: pr = perform_wins(tb, arg_len); break;
				case STATE_CARRIER: pr = perform_carrier(); break;
				default:
				arg_len = 0;
				log_line("error: invalid state in dispatch_work\n");
				return -99;
			}
			arg_len = 0;
			if (pr == -99)
			return -99;
			cmdf |= pr;
		}
		
#line 1598 "ifchd-parse.c"

		goto _st126;
		_ctr39:
			{
#line 93 "ifchd-parse.rl"
			
			ptrdiff_t al = p - arg_start;
			if (al < 0 || (size_t)al > sizeof tb - 1) {
				log_line("command argument would overflow\n");
				return -99;
			}
			arg_len = (size_t)al;
			memcpy(tb, arg_start, arg_len);
			tb[arg_len] = 0;
		}
		
#line 1614 "ifchd-parse.c"

			{
#line 104 "ifchd-parse.rl"
			
			int pr = 0;
			cmd_start = p + 1;
			switch (cl.state) {
				case STATE_IP4SET: pr = perform_ip4set(tb, arg_len); break;
				case STATE_TIMEZONE: pr = perform_timezone( tb, arg_len); break;
				case STATE_ROUTER: pr = perform_router(tb, arg_len); break;
				case STATE_DNS: pr = perform_dns(tb, arg_len); break;
				case STATE_LPRSVR: pr = perform_lprsvr(tb, arg_len); break;
				case STATE_HOSTNAME: pr = perform_hostname(tb, arg_len); break;
				case STATE_DOMAIN: pr = perform_domain(tb, arg_len); break;
				case STATE_IPTTL: pr = perform_ipttl(tb, arg_len); break;
				case STATE_MTU: pr = perform_mtu(tb, arg_len); break;
				case STATE_NTPSVR: pr = perform_ntpsrv(tb, arg_len); break;
				case STATE_WINS: pr = perform_wins(tb, arg_len); break;
				case STATE_CARRIER: pr = perform_carrier(); break;
				default:
				arg_len = 0;
				log_line("error: invalid state in dispatch_work\n");
				return -99;
			}
			arg_len = 0;
			if (pr == -99)
			return -99;
			cmdf |= pr;
		}
		
#line 1644 "ifchd-parse.c"

		goto _st126;
		_st126:
		p+= 1;
		st_case_126:
		if ( p == pe )
			goto _out126;
		switch( ( (*( p))) ) {
			case 99: {
				goto _ctr2;
			}
			case 100: {
				goto _ctr3;
			}
			case 104: {
				goto _ctr4;
			}
			case 105: {
				goto _ctr5;
			}
			case 108: {
				goto _ctr6;
			}
			case 109: {
				goto _ctr7;
			}
			case 110: {
				goto _ctr8;
			}
			case 114: {
				goto _ctr9;
			}
			case 116: {
				goto _ctr10;
			}
			case 119: {
				goto _ctr11;
			}
		}
		goto _st0;
		_ctr3:
			{
#line 91 "ifchd-parse.rl"
			cl.state = STATE_NOTHING; }
		
#line 1689 "ifchd-parse.c"

		goto _st10;
		_st10:
		p+= 1;
		st_case_10:
		if ( p == pe )
			goto _out10;
		switch( ( (*( p))) ) {
			case 110: {
				goto _st11;
			}
			case 111: {
				goto _st30;
			}
		}
		goto _st0;
		_st11:
		p+= 1;
		st_case_11:
		if ( p == pe )
			goto _out11;
		if ( ( (*( p))) == 115 ) {
			goto _st12;
		}
		goto _st0;
		_st12:
		p+= 1;
		st_case_12:
		if ( p == pe )
			goto _out12;
		if ( ( (*( p))) == 58 ) {
			goto _st13;
		}
		goto _st0;
		_st13:
		p+= 1;
		st_case_13:
		if ( p == pe )
			goto _out13;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _ctr26;
		}
		goto _st0;
		_ctr26:
			{
#line 143 "ifchd-parse.rl"
			cl.state = STATE_DNS; }
		
#line 1737 "ifchd-parse.c"

			{
#line 92 "ifchd-parse.rl"
			arg_start = p; }
		
#line 1742 "ifchd-parse.c"

		goto _st14;
		_ctr115:
			{
#line 144 "ifchd-parse.rl"
			cl.state = STATE_LPRSVR; }
		
#line 1749 "ifchd-parse.c"

			{
#line 92 "ifchd-parse.rl"
			arg_start = p; }
		
#line 1754 "ifchd-parse.c"

		goto _st14;
		_ctr126:
			{
#line 145 "ifchd-parse.rl"
			cl.state = STATE_NTPSVR; }
		
#line 1761 "ifchd-parse.c"

			{
#line 92 "ifchd-parse.rl"
			arg_start = p; }
		
#line 1766 "ifchd-parse.c"

		goto _st14;
		_ctr148:
			{
#line 146 "ifchd-parse.rl"
			cl.state = STATE_WINS; }
		
#line 1773 "ifchd-parse.c"

			{
#line 92 "ifchd-parse.rl"
			arg_start = p; }
		
#line 1778 "ifchd-parse.c"

		goto _st14;
		_st14:
		p+= 1;
		st_case_14:
		if ( p == pe )
			goto _out14;
		if ( ( (*( p))) == 46 ) {
			goto _st15;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st28;
		}
		goto _st0;
		_st15:
		p+= 1;
		st_case_15:
		if ( p == pe )
			goto _out15;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st16;
		}
		goto _st0;
		_st16:
		p+= 1;
		st_case_16:
		if ( p == pe )
			goto _out16;
		if ( ( (*( p))) == 46 ) {
			goto _st17;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st26;
		}
		goto _st0;
		_st17:
		p+= 1;
		st_case_17:
		if ( p == pe )
			goto _out17;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st18;
		}
		goto _st0;
		_st18:
		p+= 1;
		st_case_18:
		if ( p == pe )
			goto _out18;
		if ( ( (*( p))) == 46 ) {
			goto _st19;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st24;
		}
		goto _st0;
		_st19:
		p+= 1;
		st_case_19:
		if ( p == pe )
			goto _out19;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st20;
		}
		goto _st0;
		_st20:
		p+= 1;
		st_case_20:
		if ( p == pe )
			goto _out20;
		switch( ( (*( p))) ) {
			case 44: {
				goto _st21;
			}
			case 59: {
				goto _ctr39;
			}
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st22;
		}
		goto _st0;
		_st21:
		p+= 1;
		st_case_21:
		if ( p == pe )
			goto _out21;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st14;
		}
		goto _st0;
		_st22:
		p+= 1;
		st_case_22:
		if ( p == pe )
			goto _out22;
		switch( ( (*( p))) ) {
			case 44: {
				goto _st21;
			}
			case 59: {
				goto _ctr39;
			}
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st23;
		}
		goto _st0;
		_st23:
		p+= 1;
		st_case_23:
		if ( p == pe )
			goto _out23;
		switch( ( (*( p))) ) {
			case 44: {
				goto _st21;
			}
			case 59: {
				goto _ctr39;
			}
		}
		goto _st0;
		_st24:
		p+= 1;
		st_case_24:
		if ( p == pe )
			goto _out24;
		if ( ( (*( p))) == 46 ) {
			goto _st19;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st25;
		}
		goto _st0;
		_st25:
		p+= 1;
		st_case_25:
		if ( p == pe )
			goto _out25;
		if ( ( (*( p))) == 46 ) {
			goto _st19;
		}
		goto _st0;
		_st26:
		p+= 1;
		st_case_26:
		if ( p == pe )
			goto _out26;
		if ( ( (*( p))) == 46 ) {
			goto _st17;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st27;
		}
		goto _st0;
		_st27:
		p+= 1;
		st_case_27:
		if ( p == pe )
			goto _out27;
		if ( ( (*( p))) == 46 ) {
			goto _st17;
		}
		goto _st0;
		_st28:
		p+= 1;
		st_case_28:
		if ( p == pe )
			goto _out28;
		if ( ( (*( p))) == 46 ) {
			goto _st15;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st29;
		}
		goto _st0;
		_st29:
		p+= 1;
		st_case_29:
		if ( p == pe )
			goto _out29;
		if ( ( (*( p))) == 46 ) {
			goto _st15;
		}
		goto _st0;
		_st30:
		p+= 1;
		st_case_30:
		if ( p == pe )
			goto _out30;
		if ( ( (*( p))) == 109 ) {
			goto _st31;
		}
		goto _st0;
		_st31:
		p+= 1;
		st_case_31:
		if ( p == pe )
			goto _out31;
		if ( ( (*( p))) == 58 ) {
			goto _st32;
		}
		goto _st0;
		_st32:
		p+= 1;
		st_case_32:
		if ( p == pe )
			goto _out32;
		switch( ( (*( p))) ) {
			case 0: {
				goto _st0;
			}
			case 59: {
				goto _st0;
			}
		}
		goto _ctr46;
		_ctr46:
			{
#line 149 "ifchd-parse.rl"
			cl.state = STATE_DOMAIN; }
		
#line 2000 "ifchd-parse.c"

			{
#line 92 "ifchd-parse.rl"
			arg_start = p; }
		
#line 2005 "ifchd-parse.c"

		goto _st33;
		_ctr53:
			{
#line 148 "ifchd-parse.rl"
			cl.state = STATE_HOSTNAME; }
		
#line 2012 "ifchd-parse.c"

			{
#line 92 "ifchd-parse.rl"
			arg_start = p; }
		
#line 2017 "ifchd-parse.c"

		goto _st33;
		_st33:
		p+= 1;
		st_case_33:
		if ( p == pe )
			goto _out33;
		switch( ( (*( p))) ) {
			case 0: {
				goto _st0;
			}
			case 59: {
				goto _ctr39;
			}
		}
		goto _st33;
		_ctr4:
			{
#line 91 "ifchd-parse.rl"
			cl.state = STATE_NOTHING; }
		
#line 2038 "ifchd-parse.c"

		goto _st34;
		_st34:
		p+= 1;
		st_case_34:
		if ( p == pe )
			goto _out34;
		if ( ( (*( p))) == 111 ) {
			goto _st35;
		}
		goto _st0;
		_st35:
		p+= 1;
		st_case_35:
		if ( p == pe )
			goto _out35;
		if ( ( (*( p))) == 115 ) {
			goto _st36;
		}
		goto _st0;
		_st36:
		p+= 1;
		st_case_36:
		if ( p == pe )
			goto _out36;
		if ( ( (*( p))) == 116 ) {
			goto _st37;
		}
		goto _st0;
		_st37:
		p+= 1;
		st_case_37:
		if ( p == pe )
			goto _out37;
		if ( ( (*( p))) == 58 ) {
			goto _st38;
		}
		goto _st0;
		_st38:
		p+= 1;
		st_case_38:
		if ( p == pe )
			goto _out38;
		switch( ( (*( p))) ) {
			case 0: {
				goto _st0;
			}
			case 59: {
				goto _st0;
			}
		}
		goto _ctr53;
		_ctr5:
			{
#line 91 "ifchd-parse.rl"
			cl.state = STATE_NOTHING; }
		
#line 2095 "ifchd-parse.c"

		goto _st39;
		_st39:
		p+= 1;
		st_case_39:
		if ( p == pe )
			goto _out39;
		if ( ( (*( p))) == 112 ) {
			goto _st40;
		}
		goto _st0;
		_st40:
		p+= 1;
		st_case_40:
		if ( p == pe )
			goto _out40;
		switch( ( (*( p))) ) {
			case 52: {
				goto _st41;
			}
			case 116: {
				goto _st90;
			}
		}
		goto _st0;
		_st41:
		p+= 1;
		st_case_41:
		if ( p == pe )
			goto _out41;
		if ( ( (*( p))) == 58 ) {
			goto _st42;
		}
		goto _st0;
		_st42:
		p+= 1;
		st_case_42:
		if ( p == pe )
			goto _out42;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _ctr59;
		}
		goto _st0;
		_ctr59:
			{
#line 142 "ifchd-parse.rl"
			cl.state = STATE_IP4SET; }
		
#line 2143 "ifchd-parse.c"

			{
#line 92 "ifchd-parse.rl"
			arg_start = p; }
		
#line 2148 "ifchd-parse.c"

		goto _st43;
		_st43:
		p+= 1;
		st_case_43:
		if ( p == pe )
			goto _out43;
		if ( ( (*( p))) == 46 ) {
			goto _st44;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st88;
		}
		goto _st0;
		_st44:
		p+= 1;
		st_case_44:
		if ( p == pe )
			goto _out44;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st45;
		}
		goto _st0;
		_st45:
		p+= 1;
		st_case_45:
		if ( p == pe )
			goto _out45;
		if ( ( (*( p))) == 46 ) {
			goto _st46;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st86;
		}
		goto _st0;
		_st46:
		p+= 1;
		st_case_46:
		if ( p == pe )
			goto _out46;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st47;
		}
		goto _st0;
		_st47:
		p+= 1;
		st_case_47:
		if ( p == pe )
			goto _out47;
		if ( ( (*( p))) == 46 ) {
			goto _st48;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st84;
		}
		goto _st0;
		_st48:
		p+= 1;
		st_case_48:
		if ( p == pe )
			goto _out48;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st49;
		}
		goto _st0;
		_st49:
		p+= 1;
		st_case_49:
		if ( p == pe )
			goto _out49;
		if ( ( (*( p))) == 44 ) {
			goto _st50;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st82;
		}
		goto _st0;
		_st50:
		p+= 1;
		st_case_50:
		if ( p == pe )
			goto _out50;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st51;
		}
		goto _st0;
		_st51:
		p+= 1;
		st_case_51:
		if ( p == pe )
			goto _out51;
		if ( ( (*( p))) == 46 ) {
			goto _st52;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st80;
		}
		goto _st0;
		_st52:
		p+= 1;
		st_case_52:
		if ( p == pe )
			goto _out52;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st53;
		}
		goto _st0;
		_st53:
		p+= 1;
		st_case_53:
		if ( p == pe )
			goto _out53;
		if ( ( (*( p))) == 46 ) {
			goto _st54;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st78;
		}
		goto _st0;
		_st54:
		p+= 1;
		st_case_54:
		if ( p == pe )
			goto _out54;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st55;
		}
		goto _st0;
		_st55:
		p+= 1;
		st_case_55:
		if ( p == pe )
			goto _out55;
		if ( ( (*( p))) == 46 ) {
			goto _st56;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st76;
		}
		goto _st0;
		_st56:
		p+= 1;
		st_case_56:
		if ( p == pe )
			goto _out56;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st57;
		}
		goto _st0;
		_st57:
		p+= 1;
		st_case_57:
		if ( p == pe )
			goto _out57;
		switch( ( (*( p))) ) {
			case 44: {
				goto _st58;
			}
			case 59: {
				goto _ctr39;
			}
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st74;
		}
		goto _st0;
		_st58:
		p+= 1;
		st_case_58:
		if ( p == pe )
			goto _out58;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st59;
		}
		goto _st0;
		_ctr133:
			{
#line 141 "ifchd-parse.rl"
			cl.state = STATE_ROUTER; }
		
#line 2328 "ifchd-parse.c"

			{
#line 92 "ifchd-parse.rl"
			arg_start = p; }
		
#line 2333 "ifchd-parse.c"

		goto _st59;
		_st59:
		p+= 1;
		st_case_59:
		if ( p == pe )
			goto _out59;
		if ( ( (*( p))) == 46 ) {
			goto _st60;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st72;
		}
		goto _st0;
		_st60:
		p+= 1;
		st_case_60:
		if ( p == pe )
			goto _out60;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st61;
		}
		goto _st0;
		_st61:
		p+= 1;
		st_case_61:
		if ( p == pe )
			goto _out61;
		if ( ( (*( p))) == 46 ) {
			goto _st62;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st70;
		}
		goto _st0;
		_st62:
		p+= 1;
		st_case_62:
		if ( p == pe )
			goto _out62;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st63;
		}
		goto _st0;
		_st63:
		p+= 1;
		st_case_63:
		if ( p == pe )
			goto _out63;
		if ( ( (*( p))) == 46 ) {
			goto _st64;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st68;
		}
		goto _st0;
		_st64:
		p+= 1;
		st_case_64:
		if ( p == pe )
			goto _out64;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st65;
		}
		goto _st0;
		_st65:
		p+= 1;
		st_case_65:
		if ( p == pe )
			goto _out65;
		if ( ( (*( p))) == 59 ) {
			goto _ctr39;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st66;
		}
		goto _st0;
		_st66:
		p+= 1;
		st_case_66:
		if ( p == pe )
			goto _out66;
		if ( ( (*( p))) == 59 ) {
			goto _ctr39;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st67;
		}
		goto _st0;
		_ctr110:
			{
#line 153 "ifchd-parse.rl"
			cl.state = STATE_IPTTL; }
		
#line 2427 "ifchd-parse.c"

			{
#line 92 "ifchd-parse.rl"
			arg_start = p; }
		
#line 2432 "ifchd-parse.c"

		goto _st67;
		_st67:
		p+= 1;
		st_case_67:
		if ( p == pe )
			goto _out67;
		if ( ( (*( p))) == 59 ) {
			goto _ctr39;
		}
		goto _st0;
		_st68:
		p+= 1;
		st_case_68:
		if ( p == pe )
			goto _out68;
		if ( ( (*( p))) == 46 ) {
			goto _st64;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st69;
		}
		goto _st0;
		_st69:
		p+= 1;
		st_case_69:
		if ( p == pe )
			goto _out69;
		if ( ( (*( p))) == 46 ) {
			goto _st64;
		}
		goto _st0;
		_st70:
		p+= 1;
		st_case_70:
		if ( p == pe )
			goto _out70;
		if ( ( (*( p))) == 46 ) {
			goto _st62;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st71;
		}
		goto _st0;
		_st71:
		p+= 1;
		st_case_71:
		if ( p == pe )
			goto _out71;
		if ( ( (*( p))) == 46 ) {
			goto _st62;
		}
		goto _st0;
		_st72:
		p+= 1;
		st_case_72:
		if ( p == pe )
			goto _out72;
		if ( ( (*( p))) == 46 ) {
			goto _st60;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st73;
		}
		goto _st0;
		_st73:
		p+= 1;
		st_case_73:
		if ( p == pe )
			goto _out73;
		if ( ( (*( p))) == 46 ) {
			goto _st60;
		}
		goto _st0;
		_st74:
		p+= 1;
		st_case_74:
		if ( p == pe )
			goto _out74;
		switch( ( (*( p))) ) {
			case 44: {
				goto _st58;
			}
			case 59: {
				goto _ctr39;
			}
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st75;
		}
		goto _st0;
		_st75:
		p+= 1;
		st_case_75:
		if ( p == pe )
			goto _out75;
		switch( ( (*( p))) ) {
			case 44: {
				goto _st58;
			}
			case 59: {
				goto _ctr39;
			}
		}
		goto _st0;
		_st76:
		p+= 1;
		st_case_76:
		if ( p == pe )
			goto _out76;
		if ( ( (*( p))) == 46 ) {
			goto _st56;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st77;
		}
		goto _st0;
		_st77:
		p+= 1;
		st_case_77:
		if ( p == pe )
			goto _out77;
		if ( ( (*( p))) == 46 ) {
			goto _st56;
		}
		goto _st0;
		_st78:
		p+= 1;
		st_case_78:
		if ( p == pe )
			goto _out78;
		if ( ( (*( p))) == 46 ) {
			goto _st54;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st79;
		}
		goto _st0;
		_st79:
		p+= 1;
		st_case_79:
		if ( p == pe )
			goto _out79;
		if ( ( (*( p))) == 46 ) {
			goto _st54;
		}
		goto _st0;
		_st80:
		p+= 1;
		st_case_80:
		if ( p == pe )
			goto _out80;
		if ( ( (*( p))) == 46 ) {
			goto _st52;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st81;
		}
		goto _st0;
		_st81:
		p+= 1;
		st_case_81:
		if ( p == pe )
			goto _out81;
		if ( ( (*( p))) == 46 ) {
			goto _st52;
		}
		goto _st0;
		_st82:
		p+= 1;
		st_case_82:
		if ( p == pe )
			goto _out82;
		if ( ( (*( p))) == 44 ) {
			goto _st50;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st83;
		}
		goto _st0;
		_st83:
		p+= 1;
		st_case_83:
		if ( p == pe )
			goto _out83;
		if ( ( (*( p))) == 44 ) {
			goto _st50;
		}
		goto _st0;
		_st84:
		p+= 1;
		st_case_84:
		if ( p == pe )
			goto _out84;
		if ( ( (*( p))) == 46 ) {
			goto _st48;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st85;
		}
		goto _st0;
		_st85:
		p+= 1;
		st_case_85:
		if ( p == pe )
			goto _out85;
		if ( ( (*( p))) == 46 ) {
			goto _st48;
		}
		goto _st0;
		_st86:
		p+= 1;
		st_case_86:
		if ( p == pe )
			goto _out86;
		if ( ( (*( p))) == 46 ) {
			goto _st46;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st87;
		}
		goto _st0;
		_st87:
		p+= 1;
		st_case_87:
		if ( p == pe )
			goto _out87;
		if ( ( (*( p))) == 46 ) {
			goto _st46;
		}
		goto _st0;
		_st88:
		p+= 1;
		st_case_88:
		if ( p == pe )
			goto _out88;
		if ( ( (*( p))) == 46 ) {
			goto _st44;
		}
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _st89;
		}
		goto _st0;
		_st89:
		p+= 1;
		st_case_89:
		if ( p == pe )
			goto _out89;
		if ( ( (*( p))) == 46 ) {
			goto _st44;
		}
		goto _st0;
		_st90:
		p+= 1;
		st_case_90:
		if ( p == pe )
			goto _out90;
		if ( ( (*( p))) == 116 ) {
			goto _st91;
		}
		goto _st0;
		_st91:
		p+= 1;
		st_case_91:
		if ( p == pe )
			goto _out91;
		if ( ( (*( p))) == 108 ) {
			goto _st92;
		}
		goto _st0;
		_st92:
		p+= 1;
		st_case_92:
		if ( p == pe )
			goto _out92;
		if ( ( (*( p))) == 58 ) {
			goto _st93;
		}
		goto _st0;
		_st93:
		p+= 1;
		st_case_93:
		if ( p == pe )
			goto _out93;
		goto _ctr110;
		_ctr6:
			{
#line 91 "ifchd-parse.rl"
			cl.state = STATE_NOTHING; }
		
#line 2722 "ifchd-parse.c"

		goto _st94;
		_st94:
		p+= 1;
		st_case_94:
		if ( p == pe )
			goto _out94;
		if ( ( (*( p))) == 112 ) {
			goto _st95;
		}
		goto _st0;
		_st95:
		p+= 1;
		st_case_95:
		if ( p == pe )
			goto _out95;
		if ( ( (*( p))) == 114 ) {
			goto _st96;
		}
		goto _st0;
		_st96:
		p+= 1;
		st_case_96:
		if ( p == pe )
			goto _out96;
		if ( ( (*( p))) == 58 ) {
			goto _st97;
		}
		goto _st0;
		_st97:
		p+= 1;
		st_case_97:
		if ( p == pe )
			goto _out97;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _ctr115;
		}
		goto _st0;
		_ctr7:
			{
#line 91 "ifchd-parse.rl"
			cl.state = STATE_NOTHING; }
		
#line 2765 "ifchd-parse.c"

		goto _st98;
		_st98:
		p+= 1;
		st_case_98:
		if ( p == pe )
			goto _out98;
		if ( ( (*( p))) == 116 ) {
			goto _st99;
		}
		goto _st0;
		_st99:
		p+= 1;
		st_case_99:
		if ( p == pe )
			goto _out99;
		if ( ( (*( p))) == 117 ) {
			goto _st100;
		}
		goto _st0;
		_st100:
		p+= 1;
		st_case_100:
		if ( p == pe )
			goto _out100;
		if ( ( (*( p))) == 58 ) {
			goto _st101;
		}
		goto _st0;
		_st101:
		p+= 1;
		st_case_101:
		if ( p == pe )
			goto _out101;
		goto _ctr120;
		_ctr120:
			{
#line 152 "ifchd-parse.rl"
			cl.state = STATE_MTU; }
		
#line 2805 "ifchd-parse.c"

			{
#line 92 "ifchd-parse.rl"
			arg_start = p; }
		
#line 2810 "ifchd-parse.c"

		goto _st102;
		_st102:
		p+= 1;
		st_case_102:
		if ( p == pe )
			goto _out102;
		goto _st67;
		_ctr8:
			{
#line 91 "ifchd-parse.rl"
			cl.state = STATE_NOTHING; }
		
#line 2823 "ifchd-parse.c"

		goto _st103;
		_st103:
		p+= 1;
		st_case_103:
		if ( p == pe )
			goto _out103;
		if ( ( (*( p))) == 116 ) {
			goto _st104;
		}
		goto _st0;
		_st104:
		p+= 1;
		st_case_104:
		if ( p == pe )
			goto _out104;
		if ( ( (*( p))) == 112 ) {
			goto _st105;
		}
		goto _st0;
		_st105:
		p+= 1;
		st_case_105:
		if ( p == pe )
			goto _out105;
		if ( ( (*( p))) == 58 ) {
			goto _st106;
		}
		goto _st0;
		_st106:
		p+= 1;
		st_case_106:
		if ( p == pe )
			goto _out106;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _ctr126;
		}
		goto _st0;
		_ctr9:
			{
#line 91 "ifchd-parse.rl"
			cl.state = STATE_NOTHING; }
		
#line 2866 "ifchd-parse.c"

		goto _st107;
		_st107:
		p+= 1;
		st_case_107:
		if ( p == pe )
			goto _out107;
		if ( ( (*( p))) == 111 ) {
			goto _st108;
		}
		goto _st0;
		_st108:
		p+= 1;
		st_case_108:
		if ( p == pe )
			goto _out108;
		if ( ( (*( p))) == 117 ) {
			goto _st109;
		}
		goto _st0;
		_st109:
		p+= 1;
		st_case_109:
		if ( p == pe )
			goto _out109;
		if ( ( (*( p))) == 116 ) {
			goto _st110;
		}
		goto _st0;
		_st110:
		p+= 1;
		st_case_110:
		if ( p == pe )
			goto _out110;
		if ( ( (*( p))) == 114 ) {
			goto _st111;
		}
		goto _st0;
		_st111:
		p+= 1;
		st_case_111:
		if ( p == pe )
			goto _out111;
		if ( ( (*( p))) == 58 ) {
			goto _st112;
		}
		goto _st0;
		_st112:
		p+= 1;
		st_case_112:
		if ( p == pe )
			goto _out112;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _ctr133;
		}
		goto _st0;
		_ctr10:
			{
#line 91 "ifchd-parse.rl"
			cl.state = STATE_NOTHING; }
		
#line 2927 "ifchd-parse.c"

		goto _st113;
		_st113:
		p+= 1;
		st_case_113:
		if ( p == pe )
			goto _out113;
		if ( ( (*( p))) == 122 ) {
			goto _st114;
		}
		goto _st0;
		_st114:
		p+= 1;
		st_case_114:
		if ( p == pe )
			goto _out114;
		if ( ( (*( p))) == 111 ) {
			goto _st115;
		}
		goto _st0;
		_st115:
		p+= 1;
		st_case_115:
		if ( p == pe )
			goto _out115;
		if ( ( (*( p))) == 110 ) {
			goto _st116;
		}
		goto _st0;
		_st116:
		p+= 1;
		st_case_116:
		if ( p == pe )
			goto _out116;
		if ( ( (*( p))) == 101 ) {
			goto _st117;
		}
		goto _st0;
		_st117:
		p+= 1;
		st_case_117:
		if ( p == pe )
			goto _out117;
		if ( ( (*( p))) == 58 ) {
			goto _st118;
		}
		goto _st0;
		_st118:
		p+= 1;
		st_case_118:
		if ( p == pe )
			goto _out118;
		goto _ctr140;
		_ctr140:
			{
#line 151 "ifchd-parse.rl"
			cl.state = STATE_TIMEZONE; }
		
#line 2985 "ifchd-parse.c"

			{
#line 92 "ifchd-parse.rl"
			arg_start = p; }
		
#line 2990 "ifchd-parse.c"

		goto _st119;
		_st119:
		p+= 1;
		st_case_119:
		if ( p == pe )
			goto _out119;
		goto _st120;
		_st120:
		p+= 1;
		st_case_120:
		if ( p == pe )
			goto _out120;
		goto _st102;
		_ctr11:
			{
#line 91 "ifchd-parse.rl"
			cl.state = STATE_NOTHING; }
		
#line 3009 "ifchd-parse.c"

		goto _st121;
		_st121:
		p+= 1;
		st_case_121:
		if ( p == pe )
			goto _out121;
		if ( ( (*( p))) == 105 ) {
			goto _st122;
		}
		goto _st0;
		_st122:
		p+= 1;
		st_case_122:
		if ( p == pe )
			goto _out122;
		if ( ( (*( p))) == 110 ) {
			goto _st123;
		}
		goto _st0;
		_st123:
		p+= 1;
		st_case_123:
		if ( p == pe )
			goto _out123;
		if ( ( (*( p))) == 115 ) {
			goto _st124;
		}
		goto _st0;
		_st124:
		p+= 1;
		st_case_124:
		if ( p == pe )
			goto _out124;
		if ( ( (*( p))) == 58 ) {
			goto _st125;
		}
		goto _st0;
		_st125:
		p+= 1;
		st_case_125:
		if ( p == pe )
			goto _out125;
		if ( 48 <= ( (*( p))) && ( (*( p))) <= 57 ) {
			goto _ctr148;
		}
		goto _st0;
		_out1: cs = 1; goto _out; 
		_out0: cs = 0; goto _out; 
		_out2: cs = 2; goto _out; 
		_out3: cs = 3; goto _out; 
		_out4: cs = 4; goto _out; 
		_out5: cs = 5; goto _out; 
		_out6: cs = 6; goto _out; 
		_out7: cs = 7; goto _out; 
		_out8: cs = 8; goto _out; 
		_out9: cs = 9; goto _out; 
		_out126: cs = 126; goto _out; 
		_out10: cs = 10; goto _out; 
		_out11: cs = 11; goto _out; 
		_out12: cs = 12; goto _out; 
		_out13: cs = 13; goto _out; 
		_out14: cs = 14; goto _out; 
		_out15: cs = 15; goto _out; 
		_out16: cs = 16; goto _out; 
		_out17: cs = 17; goto _out; 
		_out18: cs = 18; goto _out; 
		_out19: cs = 19; goto _out; 
		_out20: cs = 20; goto _out; 
		_out21: cs = 21; goto _out; 
		_out22: cs = 22; goto _out; 
		_out23: cs = 23; goto _out; 
		_out24: cs = 24; goto _out; 
		_out25: cs = 25; goto _out; 
		_out26: cs = 26; goto _out; 
		_out27: cs = 27; goto _out; 
		_out28: cs = 28; goto _out; 
		_out29: cs = 29; goto _out; 
		_out30: cs = 30; goto _out; 
		_out31: cs = 31; goto _out; 
		_out32: cs = 32; goto _out; 
		_out33: cs = 33; goto _out; 
		_out34: cs = 34; goto _out; 
		_out35: cs = 35; goto _out; 
		_out36: cs = 36; goto _out; 
		_out37: cs = 37; goto _out; 
		_out38: cs = 38; goto _out; 
		_out39: cs = 39; goto _out; 
		_out40: cs = 40; goto _out; 
		_out41: cs = 41; goto _out; 
		_out42: cs = 42; goto _out; 
		_out43: cs = 43; goto _out; 
		_out44: cs = 44; goto _out; 
		_out45: cs = 45; goto _out; 
		_out46: cs = 46; goto _out; 
		_out47: cs = 47; goto _out; 
		_out48: cs = 48; goto _out; 
		_out49: cs = 49; goto _out; 
		_out50: cs = 50; goto _out; 
		_out51: cs = 51; goto _out; 
		_out52: cs = 52; goto _out; 
		_out53: cs = 53; goto _out; 
		_out54: cs = 54; goto _out; 
		_out55: cs = 55; goto _out; 
		_out56: cs = 56; goto _out; 
		_out57: cs = 57; goto _out; 
		_out58: cs = 58; goto _out; 
		_out59: cs = 59; goto _out; 
		_out60: cs = 60; goto _out; 
		_out61: cs = 61; goto _out; 
		_out62: cs = 62; goto _out; 
		_out63: cs = 63; goto _out; 
		_out64: cs = 64; goto _out; 
		_out65: cs = 65; goto _out; 
		_out66: cs = 66; goto _out; 
		_out67: cs = 67; goto _out; 
		_out68: cs = 68; goto _out; 
		_out69: cs = 69; goto _out; 
		_out70: cs = 70; goto _out; 
		_out71: cs = 71; goto _out; 
		_out72: cs = 72; goto _out; 
		_out73: cs = 73; goto _out; 
		_out74: cs = 74; goto _out; 
		_out75: cs = 75; goto _out; 
		_out76: cs = 76; goto _out; 
		_out77: cs = 77; goto _out; 
		_out78: cs = 78; goto _out; 
		_out79: cs = 79; goto _out; 
		_out80: cs = 80; goto _out; 
		_out81: cs = 81; goto _out; 
		_out82: cs = 82; goto _out; 
		_out83: cs = 83; goto _out; 
		_out84: cs = 84; goto _out; 
		_out85: cs = 85; goto _out; 
		_out86: cs = 86; goto _out; 
		_out87: cs = 87; goto _out; 
		_out88: cs = 88; goto _out; 
		_out89: cs = 89; goto _out; 
		_out90: cs = 90; goto _out; 
		_out91: cs = 91; goto _out; 
		_out92: cs = 92; goto _out; 
		_out93: cs = 93; goto _out; 
		_out94: cs = 94; goto _out; 
		_out95: cs = 95; goto _out; 
		_out96: cs = 96; goto _out; 
		_out97: cs = 97; goto _out; 
		_out98: cs = 98; goto _out; 
		_out99: cs = 99; goto _out; 
		_out100: cs = 100; goto _out; 
		_out101: cs = 101; goto _out; 
		_out102: cs = 102; goto _out; 
		_out103: cs = 103; goto _out; 
		_out104: cs = 104; goto _out; 
		_out105: cs = 105; goto _out; 
		_out106: cs = 106; goto _out; 
		_out107: cs = 107; goto _out; 
		_out108: cs = 108; goto _out; 
		_out109: cs = 109; goto _out; 
		_out110: cs = 110; goto _out; 
		_out111: cs = 111; goto _out; 
		_out112: cs = 112; goto _out; 
		_out113: cs = 113; goto _out; 
		_out114: cs = 114; goto _out; 
		_out115: cs = 115; goto _out; 
		_out116: cs = 116; goto _out; 
		_out117: cs = 117; goto _out; 
		_out118: cs = 118; goto _out; 
		_out119: cs = 119; goto _out; 
		_out120: cs = 120; goto _out; 
		_out121: cs = 121; goto _out; 
		_out122: cs = 122; goto _out; 
		_out123: cs = 123; goto _out; 
		_out124: cs = 124; goto _out; 
		_out125: cs = 125; goto _out; 
		_out: {}
	}
	
#line 192 "ifchd-parse.rl"

	
	if (cs == ifchd_parser_error) {
		log_line("%s: (%s) ifch received invalid commands\n",
		client_config.interface, __func__);
		return -99;
	}
	
	if (cmd_start != pe) {
		if (!memccpy(cl.ibuf, cmd_start, 0, sizeof cl.ibuf)) {
			memset(cl.ibuf, 0, sizeof cl.ibuf);
			log_line("%s: (%s) memccpy failed\n", client_config.interface, __func__);
			return -99;
		}
	}
	
	return !cmdf ? 0 : -1;
}

