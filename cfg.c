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
#include "arp.h"
#include "ndhc.h"
#include "ifchd.h"
#include "sockd.h"
#include "nk/log.h"
#include "nk/privs.h"
#include "nk/io.h"

static void copy_cmdarg(char *dest, const char *src,
size_t destlen, const char *argname)
{
	ssize_t olen = snprintf(dest, destlen, "%s", src);
	if (olen < 0 || (size_t)olen > destlen)
		suicide("snprintf failed on %s", argname);
}

struct cfgparse {
	char buf[MAX_BUF];
	size_t buflen;
	int ternary; // = 0 nothing, -1 = false, +1 = true
	int cs;
};


#line 168 "cfg.rl"



#line 217 "cfg.rl"



#line 46 "cfg.c"
static const int file_cfg_start = 1;
static const int file_cfg_first_final = 291;
static const int file_cfg_error = 0;

static const int file_cfg_en_main = 1;


#line 219 "cfg.rl"


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
		suicide("Unable to open config file '%s'.", fname);
	
	size_t linenum = 0;
	for (;;) {
		if (lc + 1 >= sizeof l) suicide("sizeof l - 1 - lc would underflow");
			ssize_t rc = safe_read(fd, l + lc, sizeof l - 1 - lc);
		if (rc < 0)
			suicide("Error reading config file '%s'.", fname);
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
				
#line 89 "cfg.c"
				{
					ccfg.cs = (int)file_cfg_start;
				}
				
#line 252 "cfg.rl"
				
				
#line 97 "cfg.c"
				{
					switch ( ccfg.cs ) {
						case 1:
						goto st_case_1;
						case 0:
						goto st_case_0;
						case 291:
						goto st_case_291;
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
						case 126:
						goto st_case_126;
						case 127:
						goto st_case_127;
						case 128:
						goto st_case_128;
						case 129:
						goto st_case_129;
						case 130:
						goto st_case_130;
						case 131:
						goto st_case_131;
						case 132:
						goto st_case_132;
						case 133:
						goto st_case_133;
						case 134:
						goto st_case_134;
						case 135:
						goto st_case_135;
						case 136:
						goto st_case_136;
						case 137:
						goto st_case_137;
						case 138:
						goto st_case_138;
						case 139:
						goto st_case_139;
						case 140:
						goto st_case_140;
						case 141:
						goto st_case_141;
						case 142:
						goto st_case_142;
						case 143:
						goto st_case_143;
						case 144:
						goto st_case_144;
						case 145:
						goto st_case_145;
						case 146:
						goto st_case_146;
						case 147:
						goto st_case_147;
						case 148:
						goto st_case_148;
						case 149:
						goto st_case_149;
						case 150:
						goto st_case_150;
						case 151:
						goto st_case_151;
						case 152:
						goto st_case_152;
						case 153:
						goto st_case_153;
						case 154:
						goto st_case_154;
						case 155:
						goto st_case_155;
						case 156:
						goto st_case_156;
						case 157:
						goto st_case_157;
						case 158:
						goto st_case_158;
						case 159:
						goto st_case_159;
						case 160:
						goto st_case_160;
						case 161:
						goto st_case_161;
						case 162:
						goto st_case_162;
						case 163:
						goto st_case_163;
						case 164:
						goto st_case_164;
						case 165:
						goto st_case_165;
						case 166:
						goto st_case_166;
						case 167:
						goto st_case_167;
						case 168:
						goto st_case_168;
						case 169:
						goto st_case_169;
						case 170:
						goto st_case_170;
						case 171:
						goto st_case_171;
						case 172:
						goto st_case_172;
						case 173:
						goto st_case_173;
						case 174:
						goto st_case_174;
						case 175:
						goto st_case_175;
						case 176:
						goto st_case_176;
						case 177:
						goto st_case_177;
						case 178:
						goto st_case_178;
						case 179:
						goto st_case_179;
						case 180:
						goto st_case_180;
						case 181:
						goto st_case_181;
						case 182:
						goto st_case_182;
						case 183:
						goto st_case_183;
						case 184:
						goto st_case_184;
						case 185:
						goto st_case_185;
						case 186:
						goto st_case_186;
						case 187:
						goto st_case_187;
						case 188:
						goto st_case_188;
						case 189:
						goto st_case_189;
						case 190:
						goto st_case_190;
						case 191:
						goto st_case_191;
						case 192:
						goto st_case_192;
						case 193:
						goto st_case_193;
						case 194:
						goto st_case_194;
						case 195:
						goto st_case_195;
						case 196:
						goto st_case_196;
						case 197:
						goto st_case_197;
						case 198:
						goto st_case_198;
						case 199:
						goto st_case_199;
						case 200:
						goto st_case_200;
						case 201:
						goto st_case_201;
						case 202:
						goto st_case_202;
						case 203:
						goto st_case_203;
						case 204:
						goto st_case_204;
						case 205:
						goto st_case_205;
						case 206:
						goto st_case_206;
						case 207:
						goto st_case_207;
						case 208:
						goto st_case_208;
						case 209:
						goto st_case_209;
						case 210:
						goto st_case_210;
						case 211:
						goto st_case_211;
						case 212:
						goto st_case_212;
						case 213:
						goto st_case_213;
						case 214:
						goto st_case_214;
						case 215:
						goto st_case_215;
						case 216:
						goto st_case_216;
						case 217:
						goto st_case_217;
						case 218:
						goto st_case_218;
						case 219:
						goto st_case_219;
						case 220:
						goto st_case_220;
						case 221:
						goto st_case_221;
						case 222:
						goto st_case_222;
						case 223:
						goto st_case_223;
						case 224:
						goto st_case_224;
						case 225:
						goto st_case_225;
						case 226:
						goto st_case_226;
						case 227:
						goto st_case_227;
						case 228:
						goto st_case_228;
						case 229:
						goto st_case_229;
						case 230:
						goto st_case_230;
						case 231:
						goto st_case_231;
						case 232:
						goto st_case_232;
						case 233:
						goto st_case_233;
						case 234:
						goto st_case_234;
						case 235:
						goto st_case_235;
						case 236:
						goto st_case_236;
						case 237:
						goto st_case_237;
						case 238:
						goto st_case_238;
						case 239:
						goto st_case_239;
						case 240:
						goto st_case_240;
						case 241:
						goto st_case_241;
						case 242:
						goto st_case_242;
						case 243:
						goto st_case_243;
						case 244:
						goto st_case_244;
						case 245:
						goto st_case_245;
						case 246:
						goto st_case_246;
						case 247:
						goto st_case_247;
						case 248:
						goto st_case_248;
						case 249:
						goto st_case_249;
						case 250:
						goto st_case_250;
						case 251:
						goto st_case_251;
						case 252:
						goto st_case_252;
						case 253:
						goto st_case_253;
						case 254:
						goto st_case_254;
						case 255:
						goto st_case_255;
						case 256:
						goto st_case_256;
						case 257:
						goto st_case_257;
						case 258:
						goto st_case_258;
						case 259:
						goto st_case_259;
						case 260:
						goto st_case_260;
						case 261:
						goto st_case_261;
						case 262:
						goto st_case_262;
						case 263:
						goto st_case_263;
						case 264:
						goto st_case_264;
						case 265:
						goto st_case_265;
						case 266:
						goto st_case_266;
						case 267:
						goto st_case_267;
						case 268:
						goto st_case_268;
						case 269:
						goto st_case_269;
						case 270:
						goto st_case_270;
						case 271:
						goto st_case_271;
						case 272:
						goto st_case_272;
						case 273:
						goto st_case_273;
						case 274:
						goto st_case_274;
						case 275:
						goto st_case_275;
						case 276:
						goto st_case_276;
						case 277:
						goto st_case_277;
						case 278:
						goto st_case_278;
						case 279:
						goto st_case_279;
						case 280:
						goto st_case_280;
						case 281:
						goto st_case_281;
						case 282:
						goto st_case_282;
						case 283:
						goto st_case_283;
						case 284:
						goto st_case_284;
						case 285:
						goto st_case_285;
						case 286:
						goto st_case_286;
						case 287:
						goto st_case_287;
						case 288:
						goto st_case_288;
						case 289:
						goto st_case_289;
						case 290:
						goto st_case_290;
					}
					p+= 1;
					st_case_1:
					if ( p == pe )
						goto _out1;
					switch( ( (*( p))) ) {
						case 10: {
							goto _st291;
						}
						case 97: {
							goto _st2;
						}
						case 99: {
							goto _st36;
						}
						case 100: {
							goto _st55;
						}
						case 103: {
							goto _st82;
						}
						case 104: {
							goto _st94;
						}
						case 105: {
							goto _st105;
						}
						case 110: {
							goto _st128;
						}
						case 114: {
							goto _st141;
						}
						case 115: {
							goto _st201;
						}
						case 117: {
							goto _st273;
						}
						case 118: {
							goto _st280;
						}
					}
					goto _st0;
					_st0:
					st_case_0:
					goto _out0;
					_ctr34:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 739 "cfg.c"
					
					{
#line 127 "cfg.rl"
						
						int t = atoi(ccfg.buf);
						arp_probe_max = t;
						if (arp_probe_min > arp_probe_max) {
							t = arp_probe_max;
							arp_probe_max = arp_probe_min;
							arp_probe_min = t;
						}
					}
					
#line 753 "cfg.c"
					
					goto _st291;
					_ctr42:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 764 "cfg.c"
					
					{
#line 118 "cfg.rl"
						
						int t = atoi(ccfg.buf);
						arp_probe_min = t;
						if (arp_probe_min > arp_probe_max) {
							t = arp_probe_max;
							arp_probe_max = arp_probe_min;
							arp_probe_min = t;
						}
					}
					
#line 778 "cfg.c"
					
					goto _st291;
					_ctr51:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 789 "cfg.c"
					
					{
#line 113 "cfg.rl"
						
						int t = atoi(ccfg.buf);
						if (t >= 0)
						arp_probe_num = t;
					}
					
#line 799 "cfg.c"
					
					goto _st291;
					_ctr61:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 810 "cfg.c"
					
					{
#line 108 "cfg.rl"
						
						int t = atoi(ccfg.buf);
						if (t >= 0)
						arp_probe_wait = t;
					}
					
#line 820 "cfg.c"
					
					goto _st291;
					_ctr74:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 831 "cfg.c"
					
					{
#line 89 "cfg.rl"
						
						copy_cmdarg(chroot_dir, ccfg.buf, sizeof chroot_dir, "chroot");
					}
					
#line 839 "cfg.c"
					
					goto _st291;
					_ctr87:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 850 "cfg.c"
					
					{
#line 57 "cfg.rl"
						get_clientid_string(ccfg.buf, ccfg.buflen); }
					
#line 856 "cfg.c"
					
					goto _st291;
					_ctr110:
					{
#line 55 "cfg.rl"
						ccfg.ternary = -1; }
					
#line 864 "cfg.c"
					
					{
#line 151 "cfg.rl"
						
						switch (ccfg.ternary) {
							case 1: allow_hostname = 1; break;
							case -1: allow_hostname = 0; default: break;
						}
					}
					
#line 875 "cfg.c"
					
					goto _st291;
					_ctr111:
					{
#line 54 "cfg.rl"
						ccfg.ternary = 1; }
					
#line 883 "cfg.c"
					
					{
#line 151 "cfg.rl"
						
						switch (ccfg.ternary) {
							case 1: allow_hostname = 1; break;
							case -1: allow_hostname = 0; default: break;
						}
					}
					
#line 894 "cfg.c"
					
					goto _st291;
					_ctr130:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 905 "cfg.c"
					
					{
#line 136 "cfg.rl"
						
						char *q;
						long mt = strtol(ccfg.buf, &q, 10);
						if (q == ccfg.buf)
						suicide("gw-metric arg '%s' isn't a valid number", ccfg.buf);
						if (mt > INT_MAX)
						suicide("gw-metric arg '%s' is too large", ccfg.buf);
						if (mt < 0)
						mt = 0;
						client_config.metric = (int)mt;
					}
					
#line 921 "cfg.c"
					
					goto _st291;
					_ctr144:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 932 "cfg.c"
					
					{
#line 58 "cfg.rl"
						
						copy_cmdarg(client_config.hostname, ccfg.buf,
						sizeof client_config.hostname, "hostname");
					}
					
#line 941 "cfg.c"
					
					goto _st291;
					_ctr160:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 952 "cfg.c"
					
					{
#line 81 "cfg.rl"
						
						if (nk_uidgidbyname(ccfg.buf, &ifch_uid, &ifch_gid))
						suicide("invalid ifch user '%s' specified", ccfg.buf);
					}
					
#line 961 "cfg.c"
					
					goto _st291;
					_ctr174:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 972 "cfg.c"
					
					{
#line 62 "cfg.rl"
						
						copy_cmdarg(client_config.interface, ccfg.buf,
						sizeof client_config.interface, "interface");
					}
					
#line 981 "cfg.c"
					
					goto _st291;
					_ctr183:
					{
#line 55 "cfg.rl"
						ccfg.ternary = -1; }
					
#line 989 "cfg.c"
					
					{
#line 66 "cfg.rl"
						
						switch (ccfg.ternary) {
							case 1: client_config.abort_if_no_lease = true; break;
							case -1: client_config.abort_if_no_lease = false; default: break;
						}
					}
					
#line 1000 "cfg.c"
					
					goto _st291;
					_ctr184:
					{
#line 54 "cfg.rl"
						ccfg.ternary = 1; }
					
#line 1008 "cfg.c"
					
					{
#line 66 "cfg.rl"
						
						switch (ccfg.ternary) {
							case 1: client_config.abort_if_no_lease = true; break;
							case -1: client_config.abort_if_no_lease = false; default: break;
						}
					}
					
#line 1019 "cfg.c"
					
					goto _st291;
					_ctr215:
					{
#line 55 "cfg.rl"
						ccfg.ternary = -1; }
					
#line 1027 "cfg.c"
					
					{
#line 102 "cfg.rl"
						
						switch (ccfg.ternary) {
							case 1: set_arp_relentless_def(true); break;
							case -1: set_arp_relentless_def(false); default: break;
						}
					}
					
#line 1038 "cfg.c"
					
					goto _st291;
					_ctr216:
					{
#line 54 "cfg.rl"
						ccfg.ternary = 1; }
					
#line 1046 "cfg.c"
					
					{
#line 102 "cfg.rl"
						
						switch (ccfg.ternary) {
							case 1: set_arp_relentless_def(true); break;
							case -1: set_arp_relentless_def(false); default: break;
						}
					}
					
#line 1057 "cfg.c"
					
					goto _st291;
					_ctr231:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 1068 "cfg.c"
					
					{
#line 72 "cfg.rl"
						set_client_addr(ccfg.buf); }
					
#line 1074 "cfg.c"
					
					goto _st291;
					_ctr246:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 1085 "cfg.c"
					
					{
#line 147 "cfg.rl"
						
						copy_cmdarg(resolv_conf_d, ccfg.buf, sizeof resolv_conf_d,
						"resolv-conf");
					}
					
#line 1094 "cfg.c"
					
					goto _st291;
					_ctr261:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 1105 "cfg.c"
					
					{
#line 157 "cfg.rl"
						
						uint32_t t = (uint32_t)atoi(ccfg.buf);
						client_config.rfkillIdx = t;
						client_config.enable_rfkill = true;
					}
					
#line 1115 "cfg.c"
					
					goto _st291;
					_ctr280:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 1126 "cfg.c"
					
					{
#line 162 "cfg.rl"
						
						client_config.s6_notify_fd = atoi(ccfg.buf);
						client_config.enable_s6_notify = true;
					}
					
#line 1135 "cfg.c"
					
					goto _st291;
					_ctr296:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 1146 "cfg.c"
					
					{
#line 95 "cfg.rl"
						
						copy_cmdarg(script_file, ccfg.buf, sizeof script_file, "script-file");
					}
					
#line 1154 "cfg.c"
					
					goto _st291;
					_ctr316:
					{
#line 55 "cfg.rl"
						ccfg.ternary = -1; }
					
#line 1162 "cfg.c"
					
					{
#line 98 "cfg.rl"
						
						log_line("seccomp_enforce option is deprecated; please remove it");
						log_line("In the meanwhile, it is ignored and seccomp is disabled.");
					}
					
#line 1171 "cfg.c"
					
					goto _st291;
					_ctr317:
					{
#line 54 "cfg.rl"
						ccfg.ternary = 1; }
					
#line 1179 "cfg.c"
					
					{
#line 98 "cfg.rl"
						
						log_line("seccomp_enforce option is deprecated; please remove it");
						log_line("In the meanwhile, it is ignored and seccomp is disabled.");
					}
					
#line 1188 "cfg.c"
					
					goto _st291;
					_ctr336:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 1199 "cfg.c"
					
					{
#line 85 "cfg.rl"
						
						if (nk_uidgidbyname(ccfg.buf, &sockd_uid, &sockd_gid))
						suicide("invalid sockd user '%s' specified", ccfg.buf);
					}
					
#line 1208 "cfg.c"
					
					goto _st291;
					_ctr350:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 1219 "cfg.c"
					
					{
#line 92 "cfg.rl"
						
						copy_cmdarg(state_dir, ccfg.buf, sizeof state_dir, "state-dir");
					}
					
#line 1227 "cfg.c"
					
					goto _st291;
					_ctr360:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 1238 "cfg.c"
					
					{
#line 77 "cfg.rl"
						
						if (nk_uidgidbyname(ccfg.buf, &ndhc_uid, &ndhc_gid))
						suicide("invalid ndhc user '%s' specified", ccfg.buf);
					}
					
#line 1247 "cfg.c"
					
					goto _st291;
					_ctr374:
					{
#line 50 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf)
						ccfg.buf[ccfg.buflen] = 0;
					}
					
#line 1258 "cfg.c"
					
					{
#line 73 "cfg.rl"
						
						copy_cmdarg(client_config.vendor, ccfg.buf,
						sizeof client_config.vendor, "vendorid");
					}
					
#line 1267 "cfg.c"
					
					goto _st291;
					_st291:
					p+= 1;
					st_case_291:
					if ( p == pe )
						goto _out291;
					goto _st0;
					_st2:
					p+= 1;
					st_case_2:
					if ( p == pe )
						goto _out2;
					if ( ( (*( p))) == 114 ) {
						goto _st3;
					}
					goto _st0;
					_st3:
					p+= 1;
					st_case_3:
					if ( p == pe )
						goto _out3;
					if ( ( (*( p))) == 112 ) {
						goto _st4;
					}
					goto _st0;
					_st4:
					p+= 1;
					st_case_4:
					if ( p == pe )
						goto _out4;
					if ( ( (*( p))) == 45 ) {
						goto _st5;
					}
					goto _st0;
					_st5:
					p+= 1;
					st_case_5:
					if ( p == pe )
						goto _out5;
					if ( ( (*( p))) == 112 ) {
						goto _st6;
					}
					goto _st0;
					_st6:
					p+= 1;
					st_case_6:
					if ( p == pe )
						goto _out6;
					if ( ( (*( p))) == 114 ) {
						goto _st7;
					}
					goto _st0;
					_st7:
					p+= 1;
					st_case_7:
					if ( p == pe )
						goto _out7;
					if ( ( (*( p))) == 111 ) {
						goto _st8;
					}
					goto _st0;
					_st8:
					p+= 1;
					st_case_8:
					if ( p == pe )
						goto _out8;
					if ( ( (*( p))) == 98 ) {
						goto _st9;
					}
					goto _st0;
					_st9:
					p+= 1;
					st_case_9:
					if ( p == pe )
						goto _out9;
					if ( ( (*( p))) == 101 ) {
						goto _st10;
					}
					goto _st0;
					_st10:
					p+= 1;
					st_case_10:
					if ( p == pe )
						goto _out10;
					if ( ( (*( p))) == 45 ) {
						goto _st11;
					}
					goto _st0;
					_st11:
					p+= 1;
					st_case_11:
					if ( p == pe )
						goto _out11;
					switch( ( (*( p))) ) {
						case 109: {
							goto _st12;
						}
						case 110: {
							goto _st23;
						}
						case 119: {
							goto _st29;
						}
					}
					goto _st0;
					_st12:
					p+= 1;
					st_case_12:
					if ( p == pe )
						goto _out12;
					switch( ( (*( p))) ) {
						case 97: {
							goto _st13;
						}
						case 105: {
							goto _st18;
						}
					}
					goto _st0;
					_st13:
					p+= 1;
					st_case_13:
					if ( p == pe )
						goto _out13;
					if ( ( (*( p))) == 120 ) {
						goto _st14;
					}
					goto _st0;
					_st14:
					p+= 1;
					st_case_14:
					if ( p == pe )
						goto _out14;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st14;
						}
						case 32: {
							goto _st14;
						}
						case 61: {
							goto _st15;
						}
					}
					goto _st0;
					_st15:
					p+= 1;
					st_case_15:
					if ( p == pe )
						goto _out15;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr31;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr31;
						}
					}
					goto _ctr30;
					_ctr30:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 1440 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1451 "cfg.c"
					
					goto _st16;
					_ctr33:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1464 "cfg.c"
					
					goto _st16;
					_st16:
					p+= 1;
					st_case_16:
					if ( p == pe )
						goto _out16;
					if ( ( (*( p))) == 10 ) {
						goto _ctr34;
					}
					goto _ctr33;
					_ctr31:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 1485 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1496 "cfg.c"
					
					goto _st17;
					_st17:
					p+= 1;
					st_case_17:
					if ( p == pe )
						goto _out17;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr31;
						}
						case 10: {
							goto _ctr34;
						}
						case 32: {
							goto _ctr31;
						}
					}
					goto _ctr30;
					_st18:
					p+= 1;
					st_case_18:
					if ( p == pe )
						goto _out18;
					if ( ( (*( p))) == 110 ) {
						goto _st19;
					}
					goto _st0;
					_st19:
					p+= 1;
					st_case_19:
					if ( p == pe )
						goto _out19;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st19;
						}
						case 32: {
							goto _st19;
						}
						case 61: {
							goto _st20;
						}
					}
					goto _st0;
					_st20:
					p+= 1;
					st_case_20:
					if ( p == pe )
						goto _out20;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr39;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr39;
						}
					}
					goto _ctr38;
					_ctr38:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 1568 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1579 "cfg.c"
					
					goto _st21;
					_ctr41:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1592 "cfg.c"
					
					goto _st21;
					_st21:
					p+= 1;
					st_case_21:
					if ( p == pe )
						goto _out21;
					if ( ( (*( p))) == 10 ) {
						goto _ctr42;
					}
					goto _ctr41;
					_ctr39:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 1613 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1624 "cfg.c"
					
					goto _st22;
					_st22:
					p+= 1;
					st_case_22:
					if ( p == pe )
						goto _out22;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr39;
						}
						case 10: {
							goto _ctr42;
						}
						case 32: {
							goto _ctr39;
						}
					}
					goto _ctr38;
					_st23:
					p+= 1;
					st_case_23:
					if ( p == pe )
						goto _out23;
					if ( ( (*( p))) == 117 ) {
						goto _st24;
					}
					goto _st0;
					_st24:
					p+= 1;
					st_case_24:
					if ( p == pe )
						goto _out24;
					if ( ( (*( p))) == 109 ) {
						goto _st25;
					}
					goto _st0;
					_st25:
					p+= 1;
					st_case_25:
					if ( p == pe )
						goto _out25;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st25;
						}
						case 32: {
							goto _st25;
						}
						case 61: {
							goto _st26;
						}
					}
					goto _st0;
					_st26:
					p+= 1;
					st_case_26:
					if ( p == pe )
						goto _out26;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr48;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr48;
						}
					}
					goto _ctr47;
					_ctr47:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 1705 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1716 "cfg.c"
					
					goto _st27;
					_ctr50:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1729 "cfg.c"
					
					goto _st27;
					_st27:
					p+= 1;
					st_case_27:
					if ( p == pe )
						goto _out27;
					if ( ( (*( p))) == 10 ) {
						goto _ctr51;
					}
					goto _ctr50;
					_ctr48:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 1750 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1761 "cfg.c"
					
					goto _st28;
					_st28:
					p+= 1;
					st_case_28:
					if ( p == pe )
						goto _out28;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr48;
						}
						case 10: {
							goto _ctr51;
						}
						case 32: {
							goto _ctr48;
						}
					}
					goto _ctr47;
					_st29:
					p+= 1;
					st_case_29:
					if ( p == pe )
						goto _out29;
					if ( ( (*( p))) == 97 ) {
						goto _st30;
					}
					goto _st0;
					_st30:
					p+= 1;
					st_case_30:
					if ( p == pe )
						goto _out30;
					if ( ( (*( p))) == 105 ) {
						goto _st31;
					}
					goto _st0;
					_st31:
					p+= 1;
					st_case_31:
					if ( p == pe )
						goto _out31;
					if ( ( (*( p))) == 116 ) {
						goto _st32;
					}
					goto _st0;
					_st32:
					p+= 1;
					st_case_32:
					if ( p == pe )
						goto _out32;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st32;
						}
						case 32: {
							goto _st32;
						}
						case 61: {
							goto _st33;
						}
					}
					goto _st0;
					_st33:
					p+= 1;
					st_case_33:
					if ( p == pe )
						goto _out33;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr58;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr58;
						}
					}
					goto _ctr57;
					_ctr57:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 1851 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1862 "cfg.c"
					
					goto _st34;
					_ctr60:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1875 "cfg.c"
					
					goto _st34;
					_st34:
					p+= 1;
					st_case_34:
					if ( p == pe )
						goto _out34;
					if ( ( (*( p))) == 10 ) {
						goto _ctr61;
					}
					goto _ctr60;
					_ctr58:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 1896 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 1907 "cfg.c"
					
					goto _st35;
					_st35:
					p+= 1;
					st_case_35:
					if ( p == pe )
						goto _out35;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr58;
						}
						case 10: {
							goto _ctr61;
						}
						case 32: {
							goto _ctr58;
						}
					}
					goto _ctr57;
					_st36:
					p+= 1;
					st_case_36:
					if ( p == pe )
						goto _out36;
					switch( ( (*( p))) ) {
						case 104: {
							goto _st37;
						}
						case 108: {
							goto _st45;
						}
					}
					goto _st0;
					_st37:
					p+= 1;
					st_case_37:
					if ( p == pe )
						goto _out37;
					if ( ( (*( p))) == 114 ) {
						goto _st38;
					}
					goto _st0;
					_st38:
					p+= 1;
					st_case_38:
					if ( p == pe )
						goto _out38;
					if ( ( (*( p))) == 111 ) {
						goto _st39;
					}
					goto _st0;
					_st39:
					p+= 1;
					st_case_39:
					if ( p == pe )
						goto _out39;
					if ( ( (*( p))) == 111 ) {
						goto _st40;
					}
					goto _st0;
					_st40:
					p+= 1;
					st_case_40:
					if ( p == pe )
						goto _out40;
					if ( ( (*( p))) == 116 ) {
						goto _st41;
					}
					goto _st0;
					_st41:
					p+= 1;
					st_case_41:
					if ( p == pe )
						goto _out41;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st41;
						}
						case 32: {
							goto _st41;
						}
						case 61: {
							goto _st42;
						}
					}
					goto _st0;
					_st42:
					p+= 1;
					st_case_42:
					if ( p == pe )
						goto _out42;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr71;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr71;
						}
					}
					goto _ctr70;
					_ctr70:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 2020 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2031 "cfg.c"
					
					goto _st43;
					_ctr73:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2044 "cfg.c"
					
					goto _st43;
					_st43:
					p+= 1;
					st_case_43:
					if ( p == pe )
						goto _out43;
					if ( ( (*( p))) == 10 ) {
						goto _ctr74;
					}
					goto _ctr73;
					_ctr71:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 2065 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2076 "cfg.c"
					
					goto _st44;
					_st44:
					p+= 1;
					st_case_44:
					if ( p == pe )
						goto _out44;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr71;
						}
						case 10: {
							goto _ctr74;
						}
						case 32: {
							goto _ctr71;
						}
					}
					goto _ctr70;
					_st45:
					p+= 1;
					st_case_45:
					if ( p == pe )
						goto _out45;
					if ( ( (*( p))) == 105 ) {
						goto _st46;
					}
					goto _st0;
					_st46:
					p+= 1;
					st_case_46:
					if ( p == pe )
						goto _out46;
					if ( ( (*( p))) == 101 ) {
						goto _st47;
					}
					goto _st0;
					_st47:
					p+= 1;
					st_case_47:
					if ( p == pe )
						goto _out47;
					if ( ( (*( p))) == 110 ) {
						goto _st48;
					}
					goto _st0;
					_st48:
					p+= 1;
					st_case_48:
					if ( p == pe )
						goto _out48;
					if ( ( (*( p))) == 116 ) {
						goto _st49;
					}
					goto _st0;
					_st49:
					p+= 1;
					st_case_49:
					if ( p == pe )
						goto _out49;
					if ( ( (*( p))) == 105 ) {
						goto _st50;
					}
					goto _st0;
					_st50:
					p+= 1;
					st_case_50:
					if ( p == pe )
						goto _out50;
					if ( ( (*( p))) == 100 ) {
						goto _st51;
					}
					goto _st0;
					_st51:
					p+= 1;
					st_case_51:
					if ( p == pe )
						goto _out51;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st51;
						}
						case 32: {
							goto _st51;
						}
						case 61: {
							goto _st52;
						}
					}
					goto _st0;
					_st52:
					p+= 1;
					st_case_52:
					if ( p == pe )
						goto _out52;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr84;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr84;
						}
					}
					goto _ctr83;
					_ctr83:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 2193 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2204 "cfg.c"
					
					goto _st53;
					_ctr86:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2217 "cfg.c"
					
					goto _st53;
					_st53:
					p+= 1;
					st_case_53:
					if ( p == pe )
						goto _out53;
					if ( ( (*( p))) == 10 ) {
						goto _ctr87;
					}
					goto _ctr86;
					_ctr84:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 2238 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2249 "cfg.c"
					
					goto _st54;
					_st54:
					p+= 1;
					st_case_54:
					if ( p == pe )
						goto _out54;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr84;
						}
						case 10: {
							goto _ctr87;
						}
						case 32: {
							goto _ctr84;
						}
					}
					goto _ctr83;
					_st55:
					p+= 1;
					st_case_55:
					if ( p == pe )
						goto _out55;
					if ( ( (*( p))) == 104 ) {
						goto _st56;
					}
					goto _st0;
					_st56:
					p+= 1;
					st_case_56:
					if ( p == pe )
						goto _out56;
					if ( ( (*( p))) == 99 ) {
						goto _st57;
					}
					goto _st0;
					_st57:
					p+= 1;
					st_case_57:
					if ( p == pe )
						goto _out57;
					if ( ( (*( p))) == 112 ) {
						goto _st58;
					}
					goto _st0;
					_st58:
					p+= 1;
					st_case_58:
					if ( p == pe )
						goto _out58;
					if ( ( (*( p))) == 45 ) {
						goto _st59;
					}
					goto _st0;
					_st59:
					p+= 1;
					st_case_59:
					if ( p == pe )
						goto _out59;
					if ( ( (*( p))) == 115 ) {
						goto _st60;
					}
					goto _st0;
					_st60:
					p+= 1;
					st_case_60:
					if ( p == pe )
						goto _out60;
					if ( ( (*( p))) == 101 ) {
						goto _st61;
					}
					goto _st0;
					_st61:
					p+= 1;
					st_case_61:
					if ( p == pe )
						goto _out61;
					if ( ( (*( p))) == 116 ) {
						goto _st62;
					}
					goto _st0;
					_st62:
					p+= 1;
					st_case_62:
					if ( p == pe )
						goto _out62;
					if ( ( (*( p))) == 45 ) {
						goto _st63;
					}
					goto _st0;
					_st63:
					p+= 1;
					st_case_63:
					if ( p == pe )
						goto _out63;
					if ( ( (*( p))) == 104 ) {
						goto _st64;
					}
					goto _st0;
					_st64:
					p+= 1;
					st_case_64:
					if ( p == pe )
						goto _out64;
					if ( ( (*( p))) == 111 ) {
						goto _st65;
					}
					goto _st0;
					_st65:
					p+= 1;
					st_case_65:
					if ( p == pe )
						goto _out65;
					if ( ( (*( p))) == 115 ) {
						goto _st66;
					}
					goto _st0;
					_st66:
					p+= 1;
					st_case_66:
					if ( p == pe )
						goto _out66;
					if ( ( (*( p))) == 116 ) {
						goto _st67;
					}
					goto _st0;
					_st67:
					p+= 1;
					st_case_67:
					if ( p == pe )
						goto _out67;
					if ( ( (*( p))) == 110 ) {
						goto _st68;
					}
					goto _st0;
					_st68:
					p+= 1;
					st_case_68:
					if ( p == pe )
						goto _out68;
					if ( ( (*( p))) == 97 ) {
						goto _st69;
					}
					goto _st0;
					_st69:
					p+= 1;
					st_case_69:
					if ( p == pe )
						goto _out69;
					if ( ( (*( p))) == 109 ) {
						goto _st70;
					}
					goto _st0;
					_st70:
					p+= 1;
					st_case_70:
					if ( p == pe )
						goto _out70;
					if ( ( (*( p))) == 101 ) {
						goto _st71;
					}
					goto _st0;
					_st71:
					p+= 1;
					st_case_71:
					if ( p == pe )
						goto _out71;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st71;
						}
						case 32: {
							goto _st71;
						}
						case 61: {
							goto _st72;
						}
					}
					goto _st0;
					_st72:
					p+= 1;
					st_case_72:
					if ( p == pe )
						goto _out72;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st72;
						}
						case 32: {
							goto _st72;
						}
						case 48: {
							goto _st73;
						}
						case 49: {
							goto _st74;
						}
						case 102: {
							goto _st75;
						}
						case 116: {
							goto _st79;
						}
					}
					goto _st0;
					_st73:
					p+= 1;
					st_case_73:
					if ( p == pe )
						goto _out73;
					if ( ( (*( p))) == 10 ) {
						goto _ctr110;
					}
					goto _st0;
					_st74:
					p+= 1;
					st_case_74:
					if ( p == pe )
						goto _out74;
					if ( ( (*( p))) == 10 ) {
						goto _ctr111;
					}
					goto _st0;
					_st75:
					p+= 1;
					st_case_75:
					if ( p == pe )
						goto _out75;
					if ( ( (*( p))) == 97 ) {
						goto _st76;
					}
					goto _st0;
					_st76:
					p+= 1;
					st_case_76:
					if ( p == pe )
						goto _out76;
					if ( ( (*( p))) == 108 ) {
						goto _st77;
					}
					goto _st0;
					_st77:
					p+= 1;
					st_case_77:
					if ( p == pe )
						goto _out77;
					if ( ( (*( p))) == 115 ) {
						goto _st78;
					}
					goto _st0;
					_st78:
					p+= 1;
					st_case_78:
					if ( p == pe )
						goto _out78;
					if ( ( (*( p))) == 101 ) {
						goto _st73;
					}
					goto _st0;
					_st79:
					p+= 1;
					st_case_79:
					if ( p == pe )
						goto _out79;
					if ( ( (*( p))) == 114 ) {
						goto _st80;
					}
					goto _st0;
					_st80:
					p+= 1;
					st_case_80:
					if ( p == pe )
						goto _out80;
					if ( ( (*( p))) == 117 ) {
						goto _st81;
					}
					goto _st0;
					_st81:
					p+= 1;
					st_case_81:
					if ( p == pe )
						goto _out81;
					if ( ( (*( p))) == 101 ) {
						goto _st74;
					}
					goto _st0;
					_st82:
					p+= 1;
					st_case_82:
					if ( p == pe )
						goto _out82;
					if ( ( (*( p))) == 119 ) {
						goto _st83;
					}
					goto _st0;
					_st83:
					p+= 1;
					st_case_83:
					if ( p == pe )
						goto _out83;
					if ( ( (*( p))) == 45 ) {
						goto _st84;
					}
					goto _st0;
					_st84:
					p+= 1;
					st_case_84:
					if ( p == pe )
						goto _out84;
					if ( ( (*( p))) == 109 ) {
						goto _st85;
					}
					goto _st0;
					_st85:
					p+= 1;
					st_case_85:
					if ( p == pe )
						goto _out85;
					if ( ( (*( p))) == 101 ) {
						goto _st86;
					}
					goto _st0;
					_st86:
					p+= 1;
					st_case_86:
					if ( p == pe )
						goto _out86;
					if ( ( (*( p))) == 116 ) {
						goto _st87;
					}
					goto _st0;
					_st87:
					p+= 1;
					st_case_87:
					if ( p == pe )
						goto _out87;
					if ( ( (*( p))) == 114 ) {
						goto _st88;
					}
					goto _st0;
					_st88:
					p+= 1;
					st_case_88:
					if ( p == pe )
						goto _out88;
					if ( ( (*( p))) == 105 ) {
						goto _st89;
					}
					goto _st0;
					_st89:
					p+= 1;
					st_case_89:
					if ( p == pe )
						goto _out89;
					if ( ( (*( p))) == 99 ) {
						goto _st90;
					}
					goto _st0;
					_st90:
					p+= 1;
					st_case_90:
					if ( p == pe )
						goto _out90;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st90;
						}
						case 32: {
							goto _st90;
						}
						case 61: {
							goto _st91;
						}
					}
					goto _st0;
					_st91:
					p+= 1;
					st_case_91:
					if ( p == pe )
						goto _out91;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr127;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr127;
						}
					}
					goto _ctr126;
					_ctr126:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 2652 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2663 "cfg.c"
					
					goto _st92;
					_ctr129:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2676 "cfg.c"
					
					goto _st92;
					_st92:
					p+= 1;
					st_case_92:
					if ( p == pe )
						goto _out92;
					if ( ( (*( p))) == 10 ) {
						goto _ctr130;
					}
					goto _ctr129;
					_ctr127:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 2697 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2708 "cfg.c"
					
					goto _st93;
					_st93:
					p+= 1;
					st_case_93:
					if ( p == pe )
						goto _out93;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr127;
						}
						case 10: {
							goto _ctr130;
						}
						case 32: {
							goto _ctr127;
						}
					}
					goto _ctr126;
					_st94:
					p+= 1;
					st_case_94:
					if ( p == pe )
						goto _out94;
					if ( ( (*( p))) == 111 ) {
						goto _st95;
					}
					goto _st0;
					_st95:
					p+= 1;
					st_case_95:
					if ( p == pe )
						goto _out95;
					if ( ( (*( p))) == 115 ) {
						goto _st96;
					}
					goto _st0;
					_st96:
					p+= 1;
					st_case_96:
					if ( p == pe )
						goto _out96;
					if ( ( (*( p))) == 116 ) {
						goto _st97;
					}
					goto _st0;
					_st97:
					p+= 1;
					st_case_97:
					if ( p == pe )
						goto _out97;
					if ( ( (*( p))) == 110 ) {
						goto _st98;
					}
					goto _st0;
					_st98:
					p+= 1;
					st_case_98:
					if ( p == pe )
						goto _out98;
					if ( ( (*( p))) == 97 ) {
						goto _st99;
					}
					goto _st0;
					_st99:
					p+= 1;
					st_case_99:
					if ( p == pe )
						goto _out99;
					if ( ( (*( p))) == 109 ) {
						goto _st100;
					}
					goto _st0;
					_st100:
					p+= 1;
					st_case_100:
					if ( p == pe )
						goto _out100;
					if ( ( (*( p))) == 101 ) {
						goto _st101;
					}
					goto _st0;
					_st101:
					p+= 1;
					st_case_101:
					if ( p == pe )
						goto _out101;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st101;
						}
						case 32: {
							goto _st101;
						}
						case 61: {
							goto _st102;
						}
					}
					goto _st0;
					_st102:
					p+= 1;
					st_case_102:
					if ( p == pe )
						goto _out102;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr141;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr141;
						}
					}
					goto _ctr140;
					_ctr140:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 2834 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2845 "cfg.c"
					
					goto _st103;
					_ctr143:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2858 "cfg.c"
					
					goto _st103;
					_st103:
					p+= 1;
					st_case_103:
					if ( p == pe )
						goto _out103;
					if ( ( (*( p))) == 10 ) {
						goto _ctr144;
					}
					goto _ctr143;
					_ctr141:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 2879 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 2890 "cfg.c"
					
					goto _st104;
					_st104:
					p+= 1;
					st_case_104:
					if ( p == pe )
						goto _out104;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr141;
						}
						case 10: {
							goto _ctr144;
						}
						case 32: {
							goto _ctr141;
						}
					}
					goto _ctr140;
					_st105:
					p+= 1;
					st_case_105:
					if ( p == pe )
						goto _out105;
					switch( ( (*( p))) ) {
						case 102: {
							goto _st106;
						}
						case 110: {
							goto _st117;
						}
					}
					goto _st0;
					_st106:
					p+= 1;
					st_case_106:
					if ( p == pe )
						goto _out106;
					if ( ( (*( p))) == 99 ) {
						goto _st107;
					}
					goto _st0;
					_st107:
					p+= 1;
					st_case_107:
					if ( p == pe )
						goto _out107;
					if ( ( (*( p))) == 104 ) {
						goto _st108;
					}
					goto _st0;
					_st108:
					p+= 1;
					st_case_108:
					if ( p == pe )
						goto _out108;
					if ( ( (*( p))) == 45 ) {
						goto _st109;
					}
					goto _st0;
					_st109:
					p+= 1;
					st_case_109:
					if ( p == pe )
						goto _out109;
					if ( ( (*( p))) == 117 ) {
						goto _st110;
					}
					goto _st0;
					_st110:
					p+= 1;
					st_case_110:
					if ( p == pe )
						goto _out110;
					if ( ( (*( p))) == 115 ) {
						goto _st111;
					}
					goto _st0;
					_st111:
					p+= 1;
					st_case_111:
					if ( p == pe )
						goto _out111;
					if ( ( (*( p))) == 101 ) {
						goto _st112;
					}
					goto _st0;
					_st112:
					p+= 1;
					st_case_112:
					if ( p == pe )
						goto _out112;
					if ( ( (*( p))) == 114 ) {
						goto _st113;
					}
					goto _st0;
					_st113:
					p+= 1;
					st_case_113:
					if ( p == pe )
						goto _out113;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st113;
						}
						case 32: {
							goto _st113;
						}
						case 61: {
							goto _st114;
						}
					}
					goto _st0;
					_st114:
					p+= 1;
					st_case_114:
					if ( p == pe )
						goto _out114;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr157;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr157;
						}
					}
					goto _ctr156;
					_ctr156:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 3030 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 3041 "cfg.c"
					
					goto _st115;
					_ctr159:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 3054 "cfg.c"
					
					goto _st115;
					_st115:
					p+= 1;
					st_case_115:
					if ( p == pe )
						goto _out115;
					if ( ( (*( p))) == 10 ) {
						goto _ctr160;
					}
					goto _ctr159;
					_ctr157:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 3075 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 3086 "cfg.c"
					
					goto _st116;
					_st116:
					p+= 1;
					st_case_116:
					if ( p == pe )
						goto _out116;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr157;
						}
						case 10: {
							goto _ctr160;
						}
						case 32: {
							goto _ctr157;
						}
					}
					goto _ctr156;
					_st117:
					p+= 1;
					st_case_117:
					if ( p == pe )
						goto _out117;
					if ( ( (*( p))) == 116 ) {
						goto _st118;
					}
					goto _st0;
					_st118:
					p+= 1;
					st_case_118:
					if ( p == pe )
						goto _out118;
					if ( ( (*( p))) == 101 ) {
						goto _st119;
					}
					goto _st0;
					_st119:
					p+= 1;
					st_case_119:
					if ( p == pe )
						goto _out119;
					if ( ( (*( p))) == 114 ) {
						goto _st120;
					}
					goto _st0;
					_st120:
					p+= 1;
					st_case_120:
					if ( p == pe )
						goto _out120;
					if ( ( (*( p))) == 102 ) {
						goto _st121;
					}
					goto _st0;
					_st121:
					p+= 1;
					st_case_121:
					if ( p == pe )
						goto _out121;
					if ( ( (*( p))) == 97 ) {
						goto _st122;
					}
					goto _st0;
					_st122:
					p+= 1;
					st_case_122:
					if ( p == pe )
						goto _out122;
					if ( ( (*( p))) == 99 ) {
						goto _st123;
					}
					goto _st0;
					_st123:
					p+= 1;
					st_case_123:
					if ( p == pe )
						goto _out123;
					if ( ( (*( p))) == 101 ) {
						goto _st124;
					}
					goto _st0;
					_st124:
					p+= 1;
					st_case_124:
					if ( p == pe )
						goto _out124;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st124;
						}
						case 32: {
							goto _st124;
						}
						case 61: {
							goto _st125;
						}
					}
					goto _st0;
					_st125:
					p+= 1;
					st_case_125:
					if ( p == pe )
						goto _out125;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr171;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr171;
						}
					}
					goto _ctr170;
					_ctr170:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 3212 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 3223 "cfg.c"
					
					goto _st126;
					_ctr173:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 3236 "cfg.c"
					
					goto _st126;
					_st126:
					p+= 1;
					st_case_126:
					if ( p == pe )
						goto _out126;
					if ( ( (*( p))) == 10 ) {
						goto _ctr174;
					}
					goto _ctr173;
					_ctr171:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 3257 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 3268 "cfg.c"
					
					goto _st127;
					_st127:
					p+= 1;
					st_case_127:
					if ( p == pe )
						goto _out127;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr171;
						}
						case 10: {
							goto _ctr174;
						}
						case 32: {
							goto _ctr171;
						}
					}
					goto _ctr170;
					_st128:
					p+= 1;
					st_case_128:
					if ( p == pe )
						goto _out128;
					if ( ( (*( p))) == 111 ) {
						goto _st129;
					}
					goto _st0;
					_st129:
					p+= 1;
					st_case_129:
					if ( p == pe )
						goto _out129;
					if ( ( (*( p))) == 119 ) {
						goto _st130;
					}
					goto _st0;
					_st130:
					p+= 1;
					st_case_130:
					if ( p == pe )
						goto _out130;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st130;
						}
						case 32: {
							goto _st130;
						}
						case 61: {
							goto _st131;
						}
					}
					goto _st0;
					_st131:
					p+= 1;
					st_case_131:
					if ( p == pe )
						goto _out131;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st131;
						}
						case 32: {
							goto _st131;
						}
						case 48: {
							goto _st132;
						}
						case 49: {
							goto _st133;
						}
						case 102: {
							goto _st134;
						}
						case 116: {
							goto _st138;
						}
					}
					goto _st0;
					_st132:
					p+= 1;
					st_case_132:
					if ( p == pe )
						goto _out132;
					if ( ( (*( p))) == 10 ) {
						goto _ctr183;
					}
					goto _st0;
					_st133:
					p+= 1;
					st_case_133:
					if ( p == pe )
						goto _out133;
					if ( ( (*( p))) == 10 ) {
						goto _ctr184;
					}
					goto _st0;
					_st134:
					p+= 1;
					st_case_134:
					if ( p == pe )
						goto _out134;
					if ( ( (*( p))) == 97 ) {
						goto _st135;
					}
					goto _st0;
					_st135:
					p+= 1;
					st_case_135:
					if ( p == pe )
						goto _out135;
					if ( ( (*( p))) == 108 ) {
						goto _st136;
					}
					goto _st0;
					_st136:
					p+= 1;
					st_case_136:
					if ( p == pe )
						goto _out136;
					if ( ( (*( p))) == 115 ) {
						goto _st137;
					}
					goto _st0;
					_st137:
					p+= 1;
					st_case_137:
					if ( p == pe )
						goto _out137;
					if ( ( (*( p))) == 101 ) {
						goto _st132;
					}
					goto _st0;
					_st138:
					p+= 1;
					st_case_138:
					if ( p == pe )
						goto _out138;
					if ( ( (*( p))) == 114 ) {
						goto _st139;
					}
					goto _st0;
					_st139:
					p+= 1;
					st_case_139:
					if ( p == pe )
						goto _out139;
					if ( ( (*( p))) == 117 ) {
						goto _st140;
					}
					goto _st0;
					_st140:
					p+= 1;
					st_case_140:
					if ( p == pe )
						goto _out140;
					if ( ( (*( p))) == 101 ) {
						goto _st133;
					}
					goto _st0;
					_st141:
					p+= 1;
					st_case_141:
					if ( p == pe )
						goto _out141;
					switch( ( (*( p))) ) {
						case 101: {
							goto _st142;
						}
						case 102: {
							goto _st189;
						}
					}
					goto _st0;
					_st142:
					p+= 1;
					st_case_142:
					if ( p == pe )
						goto _out142;
					switch( ( (*( p))) ) {
						case 108: {
							goto _st143;
						}
						case 113: {
							goto _st169;
						}
						case 115: {
							goto _st177;
						}
					}
					goto _st0;
					_st143:
					p+= 1;
					st_case_143:
					if ( p == pe )
						goto _out143;
					if ( ( (*( p))) == 101 ) {
						goto _st144;
					}
					goto _st0;
					_st144:
					p+= 1;
					st_case_144:
					if ( p == pe )
						goto _out144;
					if ( ( (*( p))) == 110 ) {
						goto _st145;
					}
					goto _st0;
					_st145:
					p+= 1;
					st_case_145:
					if ( p == pe )
						goto _out145;
					if ( ( (*( p))) == 116 ) {
						goto _st146;
					}
					goto _st0;
					_st146:
					p+= 1;
					st_case_146:
					if ( p == pe )
						goto _out146;
					if ( ( (*( p))) == 108 ) {
						goto _st147;
					}
					goto _st0;
					_st147:
					p+= 1;
					st_case_147:
					if ( p == pe )
						goto _out147;
					if ( ( (*( p))) == 101 ) {
						goto _st148;
					}
					goto _st0;
					_st148:
					p+= 1;
					st_case_148:
					if ( p == pe )
						goto _out148;
					if ( ( (*( p))) == 115 ) {
						goto _st149;
					}
					goto _st0;
					_st149:
					p+= 1;
					st_case_149:
					if ( p == pe )
						goto _out149;
					if ( ( (*( p))) == 115 ) {
						goto _st150;
					}
					goto _st0;
					_st150:
					p+= 1;
					st_case_150:
					if ( p == pe )
						goto _out150;
					if ( ( (*( p))) == 45 ) {
						goto _st151;
					}
					goto _st0;
					_st151:
					p+= 1;
					st_case_151:
					if ( p == pe )
						goto _out151;
					if ( ( (*( p))) == 100 ) {
						goto _st152;
					}
					goto _st0;
					_st152:
					p+= 1;
					st_case_152:
					if ( p == pe )
						goto _out152;
					if ( ( (*( p))) == 101 ) {
						goto _st153;
					}
					goto _st0;
					_st153:
					p+= 1;
					st_case_153:
					if ( p == pe )
						goto _out153;
					if ( ( (*( p))) == 102 ) {
						goto _st154;
					}
					goto _st0;
					_st154:
					p+= 1;
					st_case_154:
					if ( p == pe )
						goto _out154;
					if ( ( (*( p))) == 101 ) {
						goto _st155;
					}
					goto _st0;
					_st155:
					p+= 1;
					st_case_155:
					if ( p == pe )
						goto _out155;
					if ( ( (*( p))) == 110 ) {
						goto _st156;
					}
					goto _st0;
					_st156:
					p+= 1;
					st_case_156:
					if ( p == pe )
						goto _out156;
					if ( ( (*( p))) == 115 ) {
						goto _st157;
					}
					goto _st0;
					_st157:
					p+= 1;
					st_case_157:
					if ( p == pe )
						goto _out157;
					if ( ( (*( p))) == 101 ) {
						goto _st158;
					}
					goto _st0;
					_st158:
					p+= 1;
					st_case_158:
					if ( p == pe )
						goto _out158;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st158;
						}
						case 32: {
							goto _st158;
						}
						case 61: {
							goto _st159;
						}
					}
					goto _st0;
					_st159:
					p+= 1;
					st_case_159:
					if ( p == pe )
						goto _out159;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st159;
						}
						case 32: {
							goto _st159;
						}
						case 48: {
							goto _st160;
						}
						case 49: {
							goto _st161;
						}
						case 102: {
							goto _st162;
						}
						case 116: {
							goto _st166;
						}
					}
					goto _st0;
					_st160:
					p+= 1;
					st_case_160:
					if ( p == pe )
						goto _out160;
					if ( ( (*( p))) == 10 ) {
						goto _ctr215;
					}
					goto _st0;
					_st161:
					p+= 1;
					st_case_161:
					if ( p == pe )
						goto _out161;
					if ( ( (*( p))) == 10 ) {
						goto _ctr216;
					}
					goto _st0;
					_st162:
					p+= 1;
					st_case_162:
					if ( p == pe )
						goto _out162;
					if ( ( (*( p))) == 97 ) {
						goto _st163;
					}
					goto _st0;
					_st163:
					p+= 1;
					st_case_163:
					if ( p == pe )
						goto _out163;
					if ( ( (*( p))) == 108 ) {
						goto _st164;
					}
					goto _st0;
					_st164:
					p+= 1;
					st_case_164:
					if ( p == pe )
						goto _out164;
					if ( ( (*( p))) == 115 ) {
						goto _st165;
					}
					goto _st0;
					_st165:
					p+= 1;
					st_case_165:
					if ( p == pe )
						goto _out165;
					if ( ( (*( p))) == 101 ) {
						goto _st160;
					}
					goto _st0;
					_st166:
					p+= 1;
					st_case_166:
					if ( p == pe )
						goto _out166;
					if ( ( (*( p))) == 114 ) {
						goto _st167;
					}
					goto _st0;
					_st167:
					p+= 1;
					st_case_167:
					if ( p == pe )
						goto _out167;
					if ( ( (*( p))) == 117 ) {
						goto _st168;
					}
					goto _st0;
					_st168:
					p+= 1;
					st_case_168:
					if ( p == pe )
						goto _out168;
					if ( ( (*( p))) == 101 ) {
						goto _st161;
					}
					goto _st0;
					_st169:
					p+= 1;
					st_case_169:
					if ( p == pe )
						goto _out169;
					if ( ( (*( p))) == 117 ) {
						goto _st170;
					}
					goto _st0;
					_st170:
					p+= 1;
					st_case_170:
					if ( p == pe )
						goto _out170;
					if ( ( (*( p))) == 101 ) {
						goto _st171;
					}
					goto _st0;
					_st171:
					p+= 1;
					st_case_171:
					if ( p == pe )
						goto _out171;
					if ( ( (*( p))) == 115 ) {
						goto _st172;
					}
					goto _st0;
					_st172:
					p+= 1;
					st_case_172:
					if ( p == pe )
						goto _out172;
					if ( ( (*( p))) == 116 ) {
						goto _st173;
					}
					goto _st0;
					_st173:
					p+= 1;
					st_case_173:
					if ( p == pe )
						goto _out173;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st173;
						}
						case 32: {
							goto _st173;
						}
						case 61: {
							goto _st174;
						}
					}
					goto _st0;
					_st174:
					p+= 1;
					st_case_174:
					if ( p == pe )
						goto _out174;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr228;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr228;
						}
					}
					goto _ctr227;
					_ctr227:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 3799 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 3810 "cfg.c"
					
					goto _st175;
					_ctr230:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 3823 "cfg.c"
					
					goto _st175;
					_st175:
					p+= 1;
					st_case_175:
					if ( p == pe )
						goto _out175;
					if ( ( (*( p))) == 10 ) {
						goto _ctr231;
					}
					goto _ctr230;
					_ctr228:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 3844 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 3855 "cfg.c"
					
					goto _st176;
					_st176:
					p+= 1;
					st_case_176:
					if ( p == pe )
						goto _out176;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr228;
						}
						case 10: {
							goto _ctr231;
						}
						case 32: {
							goto _ctr228;
						}
					}
					goto _ctr227;
					_st177:
					p+= 1;
					st_case_177:
					if ( p == pe )
						goto _out177;
					if ( ( (*( p))) == 111 ) {
						goto _st178;
					}
					goto _st0;
					_st178:
					p+= 1;
					st_case_178:
					if ( p == pe )
						goto _out178;
					if ( ( (*( p))) == 108 ) {
						goto _st179;
					}
					goto _st0;
					_st179:
					p+= 1;
					st_case_179:
					if ( p == pe )
						goto _out179;
					if ( ( (*( p))) == 118 ) {
						goto _st180;
					}
					goto _st0;
					_st180:
					p+= 1;
					st_case_180:
					if ( p == pe )
						goto _out180;
					if ( ( (*( p))) == 45 ) {
						goto _st181;
					}
					goto _st0;
					_st181:
					p+= 1;
					st_case_181:
					if ( p == pe )
						goto _out181;
					if ( ( (*( p))) == 99 ) {
						goto _st182;
					}
					goto _st0;
					_st182:
					p+= 1;
					st_case_182:
					if ( p == pe )
						goto _out182;
					if ( ( (*( p))) == 111 ) {
						goto _st183;
					}
					goto _st0;
					_st183:
					p+= 1;
					st_case_183:
					if ( p == pe )
						goto _out183;
					if ( ( (*( p))) == 110 ) {
						goto _st184;
					}
					goto _st0;
					_st184:
					p+= 1;
					st_case_184:
					if ( p == pe )
						goto _out184;
					if ( ( (*( p))) == 102 ) {
						goto _st185;
					}
					goto _st0;
					_st185:
					p+= 1;
					st_case_185:
					if ( p == pe )
						goto _out185;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st185;
						}
						case 32: {
							goto _st185;
						}
						case 61: {
							goto _st186;
						}
					}
					goto _st0;
					_st186:
					p+= 1;
					st_case_186:
					if ( p == pe )
						goto _out186;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr243;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr243;
						}
					}
					goto _ctr242;
					_ctr242:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 3990 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4001 "cfg.c"
					
					goto _st187;
					_ctr245:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4014 "cfg.c"
					
					goto _st187;
					_st187:
					p+= 1;
					st_case_187:
					if ( p == pe )
						goto _out187;
					if ( ( (*( p))) == 10 ) {
						goto _ctr246;
					}
					goto _ctr245;
					_ctr243:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 4035 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4046 "cfg.c"
					
					goto _st188;
					_st188:
					p+= 1;
					st_case_188:
					if ( p == pe )
						goto _out188;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr243;
						}
						case 10: {
							goto _ctr246;
						}
						case 32: {
							goto _ctr243;
						}
					}
					goto _ctr242;
					_st189:
					p+= 1;
					st_case_189:
					if ( p == pe )
						goto _out189;
					if ( ( (*( p))) == 107 ) {
						goto _st190;
					}
					goto _st0;
					_st190:
					p+= 1;
					st_case_190:
					if ( p == pe )
						goto _out190;
					if ( ( (*( p))) == 105 ) {
						goto _st191;
					}
					goto _st0;
					_st191:
					p+= 1;
					st_case_191:
					if ( p == pe )
						goto _out191;
					if ( ( (*( p))) == 108 ) {
						goto _st192;
					}
					goto _st0;
					_st192:
					p+= 1;
					st_case_192:
					if ( p == pe )
						goto _out192;
					if ( ( (*( p))) == 108 ) {
						goto _st193;
					}
					goto _st0;
					_st193:
					p+= 1;
					st_case_193:
					if ( p == pe )
						goto _out193;
					if ( ( (*( p))) == 45 ) {
						goto _st194;
					}
					goto _st0;
					_st194:
					p+= 1;
					st_case_194:
					if ( p == pe )
						goto _out194;
					if ( ( (*( p))) == 105 ) {
						goto _st195;
					}
					goto _st0;
					_st195:
					p+= 1;
					st_case_195:
					if ( p == pe )
						goto _out195;
					if ( ( (*( p))) == 100 ) {
						goto _st196;
					}
					goto _st0;
					_st196:
					p+= 1;
					st_case_196:
					if ( p == pe )
						goto _out196;
					if ( ( (*( p))) == 120 ) {
						goto _st197;
					}
					goto _st0;
					_st197:
					p+= 1;
					st_case_197:
					if ( p == pe )
						goto _out197;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st197;
						}
						case 32: {
							goto _st197;
						}
						case 61: {
							goto _st198;
						}
					}
					goto _st0;
					_st198:
					p+= 1;
					st_case_198:
					if ( p == pe )
						goto _out198;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr258;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr258;
						}
					}
					goto _ctr257;
					_ctr257:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 4181 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4192 "cfg.c"
					
					goto _st199;
					_ctr260:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4205 "cfg.c"
					
					goto _st199;
					_st199:
					p+= 1;
					st_case_199:
					if ( p == pe )
						goto _out199;
					if ( ( (*( p))) == 10 ) {
						goto _ctr261;
					}
					goto _ctr260;
					_ctr258:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 4226 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4237 "cfg.c"
					
					goto _st200;
					_st200:
					p+= 1;
					st_case_200:
					if ( p == pe )
						goto _out200;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr258;
						}
						case 10: {
							goto _ctr261;
						}
						case 32: {
							goto _ctr258;
						}
					}
					goto _ctr257;
					_st201:
					p+= 1;
					st_case_201:
					if ( p == pe )
						goto _out201;
					switch( ( (*( p))) ) {
						case 54: {
							goto _st202;
						}
						case 99: {
							goto _st213;
						}
						case 101: {
							goto _st226;
						}
						case 111: {
							goto _st250;
						}
						case 116: {
							goto _st262;
						}
					}
					goto _st0;
					_st202:
					p+= 1;
					st_case_202:
					if ( p == pe )
						goto _out202;
					if ( ( (*( p))) == 45 ) {
						goto _st203;
					}
					goto _st0;
					_st203:
					p+= 1;
					st_case_203:
					if ( p == pe )
						goto _out203;
					if ( ( (*( p))) == 110 ) {
						goto _st204;
					}
					goto _st0;
					_st204:
					p+= 1;
					st_case_204:
					if ( p == pe )
						goto _out204;
					if ( ( (*( p))) == 111 ) {
						goto _st205;
					}
					goto _st0;
					_st205:
					p+= 1;
					st_case_205:
					if ( p == pe )
						goto _out205;
					if ( ( (*( p))) == 116 ) {
						goto _st206;
					}
					goto _st0;
					_st206:
					p+= 1;
					st_case_206:
					if ( p == pe )
						goto _out206;
					if ( ( (*( p))) == 105 ) {
						goto _st207;
					}
					goto _st0;
					_st207:
					p+= 1;
					st_case_207:
					if ( p == pe )
						goto _out207;
					if ( ( (*( p))) == 102 ) {
						goto _st208;
					}
					goto _st0;
					_st208:
					p+= 1;
					st_case_208:
					if ( p == pe )
						goto _out208;
					if ( ( (*( p))) == 121 ) {
						goto _st209;
					}
					goto _st0;
					_st209:
					p+= 1;
					st_case_209:
					if ( p == pe )
						goto _out209;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st209;
						}
						case 32: {
							goto _st209;
						}
						case 61: {
							goto _st210;
						}
					}
					goto _st0;
					_st210:
					p+= 1;
					st_case_210:
					if ( p == pe )
						goto _out210;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr277;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr277;
						}
					}
					goto _ctr276;
					_ctr276:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 4386 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4397 "cfg.c"
					
					goto _st211;
					_ctr279:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4410 "cfg.c"
					
					goto _st211;
					_st211:
					p+= 1;
					st_case_211:
					if ( p == pe )
						goto _out211;
					if ( ( (*( p))) == 10 ) {
						goto _ctr280;
					}
					goto _ctr279;
					_ctr277:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 4431 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4442 "cfg.c"
					
					goto _st212;
					_st212:
					p+= 1;
					st_case_212:
					if ( p == pe )
						goto _out212;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr277;
						}
						case 10: {
							goto _ctr280;
						}
						case 32: {
							goto _ctr277;
						}
					}
					goto _ctr276;
					_st213:
					p+= 1;
					st_case_213:
					if ( p == pe )
						goto _out213;
					if ( ( (*( p))) == 114 ) {
						goto _st214;
					}
					goto _st0;
					_st214:
					p+= 1;
					st_case_214:
					if ( p == pe )
						goto _out214;
					if ( ( (*( p))) == 105 ) {
						goto _st215;
					}
					goto _st0;
					_st215:
					p+= 1;
					st_case_215:
					if ( p == pe )
						goto _out215;
					if ( ( (*( p))) == 112 ) {
						goto _st216;
					}
					goto _st0;
					_st216:
					p+= 1;
					st_case_216:
					if ( p == pe )
						goto _out216;
					if ( ( (*( p))) == 116 ) {
						goto _st217;
					}
					goto _st0;
					_st217:
					p+= 1;
					st_case_217:
					if ( p == pe )
						goto _out217;
					if ( ( (*( p))) == 45 ) {
						goto _st218;
					}
					goto _st0;
					_st218:
					p+= 1;
					st_case_218:
					if ( p == pe )
						goto _out218;
					if ( ( (*( p))) == 102 ) {
						goto _st219;
					}
					goto _st0;
					_st219:
					p+= 1;
					st_case_219:
					if ( p == pe )
						goto _out219;
					if ( ( (*( p))) == 105 ) {
						goto _st220;
					}
					goto _st0;
					_st220:
					p+= 1;
					st_case_220:
					if ( p == pe )
						goto _out220;
					if ( ( (*( p))) == 108 ) {
						goto _st221;
					}
					goto _st0;
					_st221:
					p+= 1;
					st_case_221:
					if ( p == pe )
						goto _out221;
					if ( ( (*( p))) == 101 ) {
						goto _st222;
					}
					goto _st0;
					_st222:
					p+= 1;
					st_case_222:
					if ( p == pe )
						goto _out222;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st222;
						}
						case 32: {
							goto _st222;
						}
						case 61: {
							goto _st223;
						}
					}
					goto _st0;
					_st223:
					p+= 1;
					st_case_223:
					if ( p == pe )
						goto _out223;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr293;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr293;
						}
					}
					goto _ctr292;
					_ctr292:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 4586 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4597 "cfg.c"
					
					goto _st224;
					_ctr295:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4610 "cfg.c"
					
					goto _st224;
					_st224:
					p+= 1;
					st_case_224:
					if ( p == pe )
						goto _out224;
					if ( ( (*( p))) == 10 ) {
						goto _ctr296;
					}
					goto _ctr295;
					_ctr293:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 4631 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 4642 "cfg.c"
					
					goto _st225;
					_st225:
					p+= 1;
					st_case_225:
					if ( p == pe )
						goto _out225;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr293;
						}
						case 10: {
							goto _ctr296;
						}
						case 32: {
							goto _ctr293;
						}
					}
					goto _ctr292;
					_st226:
					p+= 1;
					st_case_226:
					if ( p == pe )
						goto _out226;
					if ( ( (*( p))) == 99 ) {
						goto _st227;
					}
					goto _st0;
					_st227:
					p+= 1;
					st_case_227:
					if ( p == pe )
						goto _out227;
					if ( ( (*( p))) == 99 ) {
						goto _st228;
					}
					goto _st0;
					_st228:
					p+= 1;
					st_case_228:
					if ( p == pe )
						goto _out228;
					if ( ( (*( p))) == 111 ) {
						goto _st229;
					}
					goto _st0;
					_st229:
					p+= 1;
					st_case_229:
					if ( p == pe )
						goto _out229;
					if ( ( (*( p))) == 109 ) {
						goto _st230;
					}
					goto _st0;
					_st230:
					p+= 1;
					st_case_230:
					if ( p == pe )
						goto _out230;
					if ( ( (*( p))) == 112 ) {
						goto _st231;
					}
					goto _st0;
					_st231:
					p+= 1;
					st_case_231:
					if ( p == pe )
						goto _out231;
					if ( ( (*( p))) == 45 ) {
						goto _st232;
					}
					goto _st0;
					_st232:
					p+= 1;
					st_case_232:
					if ( p == pe )
						goto _out232;
					if ( ( (*( p))) == 101 ) {
						goto _st233;
					}
					goto _st0;
					_st233:
					p+= 1;
					st_case_233:
					if ( p == pe )
						goto _out233;
					if ( ( (*( p))) == 110 ) {
						goto _st234;
					}
					goto _st0;
					_st234:
					p+= 1;
					st_case_234:
					if ( p == pe )
						goto _out234;
					if ( ( (*( p))) == 102 ) {
						goto _st235;
					}
					goto _st0;
					_st235:
					p+= 1;
					st_case_235:
					if ( p == pe )
						goto _out235;
					if ( ( (*( p))) == 111 ) {
						goto _st236;
					}
					goto _st0;
					_st236:
					p+= 1;
					st_case_236:
					if ( p == pe )
						goto _out236;
					if ( ( (*( p))) == 114 ) {
						goto _st237;
					}
					goto _st0;
					_st237:
					p+= 1;
					st_case_237:
					if ( p == pe )
						goto _out237;
					if ( ( (*( p))) == 99 ) {
						goto _st238;
					}
					goto _st0;
					_st238:
					p+= 1;
					st_case_238:
					if ( p == pe )
						goto _out238;
					if ( ( (*( p))) == 101 ) {
						goto _st239;
					}
					goto _st0;
					_st239:
					p+= 1;
					st_case_239:
					if ( p == pe )
						goto _out239;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st239;
						}
						case 32: {
							goto _st239;
						}
						case 61: {
							goto _st240;
						}
					}
					goto _st0;
					_st240:
					p+= 1;
					st_case_240:
					if ( p == pe )
						goto _out240;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st240;
						}
						case 32: {
							goto _st240;
						}
						case 48: {
							goto _st241;
						}
						case 49: {
							goto _st242;
						}
						case 102: {
							goto _st243;
						}
						case 116: {
							goto _st247;
						}
					}
					goto _st0;
					_st241:
					p+= 1;
					st_case_241:
					if ( p == pe )
						goto _out241;
					if ( ( (*( p))) == 10 ) {
						goto _ctr316;
					}
					goto _st0;
					_st242:
					p+= 1;
					st_case_242:
					if ( p == pe )
						goto _out242;
					if ( ( (*( p))) == 10 ) {
						goto _ctr317;
					}
					goto _st0;
					_st243:
					p+= 1;
					st_case_243:
					if ( p == pe )
						goto _out243;
					if ( ( (*( p))) == 97 ) {
						goto _st244;
					}
					goto _st0;
					_st244:
					p+= 1;
					st_case_244:
					if ( p == pe )
						goto _out244;
					if ( ( (*( p))) == 108 ) {
						goto _st245;
					}
					goto _st0;
					_st245:
					p+= 1;
					st_case_245:
					if ( p == pe )
						goto _out245;
					if ( ( (*( p))) == 115 ) {
						goto _st246;
					}
					goto _st0;
					_st246:
					p+= 1;
					st_case_246:
					if ( p == pe )
						goto _out246;
					if ( ( (*( p))) == 101 ) {
						goto _st241;
					}
					goto _st0;
					_st247:
					p+= 1;
					st_case_247:
					if ( p == pe )
						goto _out247;
					if ( ( (*( p))) == 114 ) {
						goto _st248;
					}
					goto _st0;
					_st248:
					p+= 1;
					st_case_248:
					if ( p == pe )
						goto _out248;
					if ( ( (*( p))) == 117 ) {
						goto _st249;
					}
					goto _st0;
					_st249:
					p+= 1;
					st_case_249:
					if ( p == pe )
						goto _out249;
					if ( ( (*( p))) == 101 ) {
						goto _st242;
					}
					goto _st0;
					_st250:
					p+= 1;
					st_case_250:
					if ( p == pe )
						goto _out250;
					if ( ( (*( p))) == 99 ) {
						goto _st251;
					}
					goto _st0;
					_st251:
					p+= 1;
					st_case_251:
					if ( p == pe )
						goto _out251;
					if ( ( (*( p))) == 107 ) {
						goto _st252;
					}
					goto _st0;
					_st252:
					p+= 1;
					st_case_252:
					if ( p == pe )
						goto _out252;
					if ( ( (*( p))) == 100 ) {
						goto _st253;
					}
					goto _st0;
					_st253:
					p+= 1;
					st_case_253:
					if ( p == pe )
						goto _out253;
					if ( ( (*( p))) == 45 ) {
						goto _st254;
					}
					goto _st0;
					_st254:
					p+= 1;
					st_case_254:
					if ( p == pe )
						goto _out254;
					if ( ( (*( p))) == 117 ) {
						goto _st255;
					}
					goto _st0;
					_st255:
					p+= 1;
					st_case_255:
					if ( p == pe )
						goto _out255;
					if ( ( (*( p))) == 115 ) {
						goto _st256;
					}
					goto _st0;
					_st256:
					p+= 1;
					st_case_256:
					if ( p == pe )
						goto _out256;
					if ( ( (*( p))) == 101 ) {
						goto _st257;
					}
					goto _st0;
					_st257:
					p+= 1;
					st_case_257:
					if ( p == pe )
						goto _out257;
					if ( ( (*( p))) == 114 ) {
						goto _st258;
					}
					goto _st0;
					_st258:
					p+= 1;
					st_case_258:
					if ( p == pe )
						goto _out258;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st258;
						}
						case 32: {
							goto _st258;
						}
						case 61: {
							goto _st259;
						}
					}
					goto _st0;
					_st259:
					p+= 1;
					st_case_259:
					if ( p == pe )
						goto _out259;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr333;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr333;
						}
					}
					goto _ctr332;
					_ctr332:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 5018 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5029 "cfg.c"
					
					goto _st260;
					_ctr335:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5042 "cfg.c"
					
					goto _st260;
					_st260:
					p+= 1;
					st_case_260:
					if ( p == pe )
						goto _out260;
					if ( ( (*( p))) == 10 ) {
						goto _ctr336;
					}
					goto _ctr335;
					_ctr333:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 5063 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5074 "cfg.c"
					
					goto _st261;
					_st261:
					p+= 1;
					st_case_261:
					if ( p == pe )
						goto _out261;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr333;
						}
						case 10: {
							goto _ctr336;
						}
						case 32: {
							goto _ctr333;
						}
					}
					goto _ctr332;
					_st262:
					p+= 1;
					st_case_262:
					if ( p == pe )
						goto _out262;
					if ( ( (*( p))) == 97 ) {
						goto _st263;
					}
					goto _st0;
					_st263:
					p+= 1;
					st_case_263:
					if ( p == pe )
						goto _out263;
					if ( ( (*( p))) == 116 ) {
						goto _st264;
					}
					goto _st0;
					_st264:
					p+= 1;
					st_case_264:
					if ( p == pe )
						goto _out264;
					if ( ( (*( p))) == 101 ) {
						goto _st265;
					}
					goto _st0;
					_st265:
					p+= 1;
					st_case_265:
					if ( p == pe )
						goto _out265;
					if ( ( (*( p))) == 45 ) {
						goto _st266;
					}
					goto _st0;
					_st266:
					p+= 1;
					st_case_266:
					if ( p == pe )
						goto _out266;
					if ( ( (*( p))) == 100 ) {
						goto _st267;
					}
					goto _st0;
					_st267:
					p+= 1;
					st_case_267:
					if ( p == pe )
						goto _out267;
					if ( ( (*( p))) == 105 ) {
						goto _st268;
					}
					goto _st0;
					_st268:
					p+= 1;
					st_case_268:
					if ( p == pe )
						goto _out268;
					if ( ( (*( p))) == 114 ) {
						goto _st269;
					}
					goto _st0;
					_st269:
					p+= 1;
					st_case_269:
					if ( p == pe )
						goto _out269;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st269;
						}
						case 32: {
							goto _st269;
						}
						case 61: {
							goto _st270;
						}
					}
					goto _st0;
					_st270:
					p+= 1;
					st_case_270:
					if ( p == pe )
						goto _out270;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr347;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr347;
						}
					}
					goto _ctr346;
					_ctr346:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 5200 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5211 "cfg.c"
					
					goto _st271;
					_ctr349:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5224 "cfg.c"
					
					goto _st271;
					_st271:
					p+= 1;
					st_case_271:
					if ( p == pe )
						goto _out271;
					if ( ( (*( p))) == 10 ) {
						goto _ctr350;
					}
					goto _ctr349;
					_ctr347:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 5245 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5256 "cfg.c"
					
					goto _st272;
					_st272:
					p+= 1;
					st_case_272:
					if ( p == pe )
						goto _out272;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr347;
						}
						case 10: {
							goto _ctr350;
						}
						case 32: {
							goto _ctr347;
						}
					}
					goto _ctr346;
					_st273:
					p+= 1;
					st_case_273:
					if ( p == pe )
						goto _out273;
					if ( ( (*( p))) == 115 ) {
						goto _st274;
					}
					goto _st0;
					_st274:
					p+= 1;
					st_case_274:
					if ( p == pe )
						goto _out274;
					if ( ( (*( p))) == 101 ) {
						goto _st275;
					}
					goto _st0;
					_st275:
					p+= 1;
					st_case_275:
					if ( p == pe )
						goto _out275;
					if ( ( (*( p))) == 114 ) {
						goto _st276;
					}
					goto _st0;
					_st276:
					p+= 1;
					st_case_276:
					if ( p == pe )
						goto _out276;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st276;
						}
						case 32: {
							goto _st276;
						}
						case 61: {
							goto _st277;
						}
					}
					goto _st0;
					_st277:
					p+= 1;
					st_case_277:
					if ( p == pe )
						goto _out277;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr357;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr357;
						}
					}
					goto _ctr356;
					_ctr356:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 5346 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5357 "cfg.c"
					
					goto _st278;
					_ctr359:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5370 "cfg.c"
					
					goto _st278;
					_st278:
					p+= 1;
					st_case_278:
					if ( p == pe )
						goto _out278;
					if ( ( (*( p))) == 10 ) {
						goto _ctr360;
					}
					goto _ctr359;
					_ctr357:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 5391 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5402 "cfg.c"
					
					goto _st279;
					_st279:
					p+= 1;
					st_case_279:
					if ( p == pe )
						goto _out279;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr357;
						}
						case 10: {
							goto _ctr360;
						}
						case 32: {
							goto _ctr357;
						}
					}
					goto _ctr356;
					_st280:
					p+= 1;
					st_case_280:
					if ( p == pe )
						goto _out280;
					if ( ( (*( p))) == 101 ) {
						goto _st281;
					}
					goto _st0;
					_st281:
					p+= 1;
					st_case_281:
					if ( p == pe )
						goto _out281;
					if ( ( (*( p))) == 110 ) {
						goto _st282;
					}
					goto _st0;
					_st282:
					p+= 1;
					st_case_282:
					if ( p == pe )
						goto _out282;
					if ( ( (*( p))) == 100 ) {
						goto _st283;
					}
					goto _st0;
					_st283:
					p+= 1;
					st_case_283:
					if ( p == pe )
						goto _out283;
					if ( ( (*( p))) == 111 ) {
						goto _st284;
					}
					goto _st0;
					_st284:
					p+= 1;
					st_case_284:
					if ( p == pe )
						goto _out284;
					if ( ( (*( p))) == 114 ) {
						goto _st285;
					}
					goto _st0;
					_st285:
					p+= 1;
					st_case_285:
					if ( p == pe )
						goto _out285;
					if ( ( (*( p))) == 105 ) {
						goto _st286;
					}
					goto _st0;
					_st286:
					p+= 1;
					st_case_286:
					if ( p == pe )
						goto _out286;
					if ( ( (*( p))) == 100 ) {
						goto _st287;
					}
					goto _st0;
					_st287:
					p+= 1;
					st_case_287:
					if ( p == pe )
						goto _out287;
					switch( ( (*( p))) ) {
						case 9: {
							goto _st287;
						}
						case 32: {
							goto _st287;
						}
						case 61: {
							goto _st288;
						}
					}
					goto _st0;
					_st288:
					p+= 1;
					st_case_288:
					if ( p == pe )
						goto _out288;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr371;
						}
						case 10: {
							goto _st0;
						}
						case 32: {
							goto _ctr371;
						}
					}
					goto _ctr370;
					_ctr370:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 5528 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5539 "cfg.c"
					
					goto _st289;
					_ctr373:
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5552 "cfg.c"
					
					goto _st289;
					_st289:
					p+= 1;
					st_case_289:
					if ( p == pe )
						goto _out289;
					if ( ( (*( p))) == 10 ) {
						goto _ctr374;
					}
					goto _ctr373;
					_ctr371:
					{
#line 39 "cfg.rl"
						
						memset(&ccfg.buf, 0, sizeof ccfg.buf);
						ccfg.buflen = 0;
						ccfg.ternary = 0;
					}
					
#line 5573 "cfg.c"
					
					{
#line 44 "cfg.rl"
						
						if (ccfg.buflen < sizeof ccfg.buf - 1)
						ccfg.buf[ccfg.buflen++] = *p;
						else
						suicide("line or option is too long");
					}
					
#line 5584 "cfg.c"
					
					goto _st290;
					_st290:
					p+= 1;
					st_case_290:
					if ( p == pe )
						goto _out290;
					switch( ( (*( p))) ) {
						case 9: {
							goto _ctr371;
						}
						case 10: {
							goto _ctr374;
						}
						case 32: {
							goto _ctr371;
						}
					}
					goto _ctr370;
					_out1: ccfg.cs = 1; goto _out; 
					_out0: ccfg.cs = 0; goto _out; 
					_out291: ccfg.cs = 291; goto _out; 
					_out2: ccfg.cs = 2; goto _out; 
					_out3: ccfg.cs = 3; goto _out; 
					_out4: ccfg.cs = 4; goto _out; 
					_out5: ccfg.cs = 5; goto _out; 
					_out6: ccfg.cs = 6; goto _out; 
					_out7: ccfg.cs = 7; goto _out; 
					_out8: ccfg.cs = 8; goto _out; 
					_out9: ccfg.cs = 9; goto _out; 
					_out10: ccfg.cs = 10; goto _out; 
					_out11: ccfg.cs = 11; goto _out; 
					_out12: ccfg.cs = 12; goto _out; 
					_out13: ccfg.cs = 13; goto _out; 
					_out14: ccfg.cs = 14; goto _out; 
					_out15: ccfg.cs = 15; goto _out; 
					_out16: ccfg.cs = 16; goto _out; 
					_out17: ccfg.cs = 17; goto _out; 
					_out18: ccfg.cs = 18; goto _out; 
					_out19: ccfg.cs = 19; goto _out; 
					_out20: ccfg.cs = 20; goto _out; 
					_out21: ccfg.cs = 21; goto _out; 
					_out22: ccfg.cs = 22; goto _out; 
					_out23: ccfg.cs = 23; goto _out; 
					_out24: ccfg.cs = 24; goto _out; 
					_out25: ccfg.cs = 25; goto _out; 
					_out26: ccfg.cs = 26; goto _out; 
					_out27: ccfg.cs = 27; goto _out; 
					_out28: ccfg.cs = 28; goto _out; 
					_out29: ccfg.cs = 29; goto _out; 
					_out30: ccfg.cs = 30; goto _out; 
					_out31: ccfg.cs = 31; goto _out; 
					_out32: ccfg.cs = 32; goto _out; 
					_out33: ccfg.cs = 33; goto _out; 
					_out34: ccfg.cs = 34; goto _out; 
					_out35: ccfg.cs = 35; goto _out; 
					_out36: ccfg.cs = 36; goto _out; 
					_out37: ccfg.cs = 37; goto _out; 
					_out38: ccfg.cs = 38; goto _out; 
					_out39: ccfg.cs = 39; goto _out; 
					_out40: ccfg.cs = 40; goto _out; 
					_out41: ccfg.cs = 41; goto _out; 
					_out42: ccfg.cs = 42; goto _out; 
					_out43: ccfg.cs = 43; goto _out; 
					_out44: ccfg.cs = 44; goto _out; 
					_out45: ccfg.cs = 45; goto _out; 
					_out46: ccfg.cs = 46; goto _out; 
					_out47: ccfg.cs = 47; goto _out; 
					_out48: ccfg.cs = 48; goto _out; 
					_out49: ccfg.cs = 49; goto _out; 
					_out50: ccfg.cs = 50; goto _out; 
					_out51: ccfg.cs = 51; goto _out; 
					_out52: ccfg.cs = 52; goto _out; 
					_out53: ccfg.cs = 53; goto _out; 
					_out54: ccfg.cs = 54; goto _out; 
					_out55: ccfg.cs = 55; goto _out; 
					_out56: ccfg.cs = 56; goto _out; 
					_out57: ccfg.cs = 57; goto _out; 
					_out58: ccfg.cs = 58; goto _out; 
					_out59: ccfg.cs = 59; goto _out; 
					_out60: ccfg.cs = 60; goto _out; 
					_out61: ccfg.cs = 61; goto _out; 
					_out62: ccfg.cs = 62; goto _out; 
					_out63: ccfg.cs = 63; goto _out; 
					_out64: ccfg.cs = 64; goto _out; 
					_out65: ccfg.cs = 65; goto _out; 
					_out66: ccfg.cs = 66; goto _out; 
					_out67: ccfg.cs = 67; goto _out; 
					_out68: ccfg.cs = 68; goto _out; 
					_out69: ccfg.cs = 69; goto _out; 
					_out70: ccfg.cs = 70; goto _out; 
					_out71: ccfg.cs = 71; goto _out; 
					_out72: ccfg.cs = 72; goto _out; 
					_out73: ccfg.cs = 73; goto _out; 
					_out74: ccfg.cs = 74; goto _out; 
					_out75: ccfg.cs = 75; goto _out; 
					_out76: ccfg.cs = 76; goto _out; 
					_out77: ccfg.cs = 77; goto _out; 
					_out78: ccfg.cs = 78; goto _out; 
					_out79: ccfg.cs = 79; goto _out; 
					_out80: ccfg.cs = 80; goto _out; 
					_out81: ccfg.cs = 81; goto _out; 
					_out82: ccfg.cs = 82; goto _out; 
					_out83: ccfg.cs = 83; goto _out; 
					_out84: ccfg.cs = 84; goto _out; 
					_out85: ccfg.cs = 85; goto _out; 
					_out86: ccfg.cs = 86; goto _out; 
					_out87: ccfg.cs = 87; goto _out; 
					_out88: ccfg.cs = 88; goto _out; 
					_out89: ccfg.cs = 89; goto _out; 
					_out90: ccfg.cs = 90; goto _out; 
					_out91: ccfg.cs = 91; goto _out; 
					_out92: ccfg.cs = 92; goto _out; 
					_out93: ccfg.cs = 93; goto _out; 
					_out94: ccfg.cs = 94; goto _out; 
					_out95: ccfg.cs = 95; goto _out; 
					_out96: ccfg.cs = 96; goto _out; 
					_out97: ccfg.cs = 97; goto _out; 
					_out98: ccfg.cs = 98; goto _out; 
					_out99: ccfg.cs = 99; goto _out; 
					_out100: ccfg.cs = 100; goto _out; 
					_out101: ccfg.cs = 101; goto _out; 
					_out102: ccfg.cs = 102; goto _out; 
					_out103: ccfg.cs = 103; goto _out; 
					_out104: ccfg.cs = 104; goto _out; 
					_out105: ccfg.cs = 105; goto _out; 
					_out106: ccfg.cs = 106; goto _out; 
					_out107: ccfg.cs = 107; goto _out; 
					_out108: ccfg.cs = 108; goto _out; 
					_out109: ccfg.cs = 109; goto _out; 
					_out110: ccfg.cs = 110; goto _out; 
					_out111: ccfg.cs = 111; goto _out; 
					_out112: ccfg.cs = 112; goto _out; 
					_out113: ccfg.cs = 113; goto _out; 
					_out114: ccfg.cs = 114; goto _out; 
					_out115: ccfg.cs = 115; goto _out; 
					_out116: ccfg.cs = 116; goto _out; 
					_out117: ccfg.cs = 117; goto _out; 
					_out118: ccfg.cs = 118; goto _out; 
					_out119: ccfg.cs = 119; goto _out; 
					_out120: ccfg.cs = 120; goto _out; 
					_out121: ccfg.cs = 121; goto _out; 
					_out122: ccfg.cs = 122; goto _out; 
					_out123: ccfg.cs = 123; goto _out; 
					_out124: ccfg.cs = 124; goto _out; 
					_out125: ccfg.cs = 125; goto _out; 
					_out126: ccfg.cs = 126; goto _out; 
					_out127: ccfg.cs = 127; goto _out; 
					_out128: ccfg.cs = 128; goto _out; 
					_out129: ccfg.cs = 129; goto _out; 
					_out130: ccfg.cs = 130; goto _out; 
					_out131: ccfg.cs = 131; goto _out; 
					_out132: ccfg.cs = 132; goto _out; 
					_out133: ccfg.cs = 133; goto _out; 
					_out134: ccfg.cs = 134; goto _out; 
					_out135: ccfg.cs = 135; goto _out; 
					_out136: ccfg.cs = 136; goto _out; 
					_out137: ccfg.cs = 137; goto _out; 
					_out138: ccfg.cs = 138; goto _out; 
					_out139: ccfg.cs = 139; goto _out; 
					_out140: ccfg.cs = 140; goto _out; 
					_out141: ccfg.cs = 141; goto _out; 
					_out142: ccfg.cs = 142; goto _out; 
					_out143: ccfg.cs = 143; goto _out; 
					_out144: ccfg.cs = 144; goto _out; 
					_out145: ccfg.cs = 145; goto _out; 
					_out146: ccfg.cs = 146; goto _out; 
					_out147: ccfg.cs = 147; goto _out; 
					_out148: ccfg.cs = 148; goto _out; 
					_out149: ccfg.cs = 149; goto _out; 
					_out150: ccfg.cs = 150; goto _out; 
					_out151: ccfg.cs = 151; goto _out; 
					_out152: ccfg.cs = 152; goto _out; 
					_out153: ccfg.cs = 153; goto _out; 
					_out154: ccfg.cs = 154; goto _out; 
					_out155: ccfg.cs = 155; goto _out; 
					_out156: ccfg.cs = 156; goto _out; 
					_out157: ccfg.cs = 157; goto _out; 
					_out158: ccfg.cs = 158; goto _out; 
					_out159: ccfg.cs = 159; goto _out; 
					_out160: ccfg.cs = 160; goto _out; 
					_out161: ccfg.cs = 161; goto _out; 
					_out162: ccfg.cs = 162; goto _out; 
					_out163: ccfg.cs = 163; goto _out; 
					_out164: ccfg.cs = 164; goto _out; 
					_out165: ccfg.cs = 165; goto _out; 
					_out166: ccfg.cs = 166; goto _out; 
					_out167: ccfg.cs = 167; goto _out; 
					_out168: ccfg.cs = 168; goto _out; 
					_out169: ccfg.cs = 169; goto _out; 
					_out170: ccfg.cs = 170; goto _out; 
					_out171: ccfg.cs = 171; goto _out; 
					_out172: ccfg.cs = 172; goto _out; 
					_out173: ccfg.cs = 173; goto _out; 
					_out174: ccfg.cs = 174; goto _out; 
					_out175: ccfg.cs = 175; goto _out; 
					_out176: ccfg.cs = 176; goto _out; 
					_out177: ccfg.cs = 177; goto _out; 
					_out178: ccfg.cs = 178; goto _out; 
					_out179: ccfg.cs = 179; goto _out; 
					_out180: ccfg.cs = 180; goto _out; 
					_out181: ccfg.cs = 181; goto _out; 
					_out182: ccfg.cs = 182; goto _out; 
					_out183: ccfg.cs = 183; goto _out; 
					_out184: ccfg.cs = 184; goto _out; 
					_out185: ccfg.cs = 185; goto _out; 
					_out186: ccfg.cs = 186; goto _out; 
					_out187: ccfg.cs = 187; goto _out; 
					_out188: ccfg.cs = 188; goto _out; 
					_out189: ccfg.cs = 189; goto _out; 
					_out190: ccfg.cs = 190; goto _out; 
					_out191: ccfg.cs = 191; goto _out; 
					_out192: ccfg.cs = 192; goto _out; 
					_out193: ccfg.cs = 193; goto _out; 
					_out194: ccfg.cs = 194; goto _out; 
					_out195: ccfg.cs = 195; goto _out; 
					_out196: ccfg.cs = 196; goto _out; 
					_out197: ccfg.cs = 197; goto _out; 
					_out198: ccfg.cs = 198; goto _out; 
					_out199: ccfg.cs = 199; goto _out; 
					_out200: ccfg.cs = 200; goto _out; 
					_out201: ccfg.cs = 201; goto _out; 
					_out202: ccfg.cs = 202; goto _out; 
					_out203: ccfg.cs = 203; goto _out; 
					_out204: ccfg.cs = 204; goto _out; 
					_out205: ccfg.cs = 205; goto _out; 
					_out206: ccfg.cs = 206; goto _out; 
					_out207: ccfg.cs = 207; goto _out; 
					_out208: ccfg.cs = 208; goto _out; 
					_out209: ccfg.cs = 209; goto _out; 
					_out210: ccfg.cs = 210; goto _out; 
					_out211: ccfg.cs = 211; goto _out; 
					_out212: ccfg.cs = 212; goto _out; 
					_out213: ccfg.cs = 213; goto _out; 
					_out214: ccfg.cs = 214; goto _out; 
					_out215: ccfg.cs = 215; goto _out; 
					_out216: ccfg.cs = 216; goto _out; 
					_out217: ccfg.cs = 217; goto _out; 
					_out218: ccfg.cs = 218; goto _out; 
					_out219: ccfg.cs = 219; goto _out; 
					_out220: ccfg.cs = 220; goto _out; 
					_out221: ccfg.cs = 221; goto _out; 
					_out222: ccfg.cs = 222; goto _out; 
					_out223: ccfg.cs = 223; goto _out; 
					_out224: ccfg.cs = 224; goto _out; 
					_out225: ccfg.cs = 225; goto _out; 
					_out226: ccfg.cs = 226; goto _out; 
					_out227: ccfg.cs = 227; goto _out; 
					_out228: ccfg.cs = 228; goto _out; 
					_out229: ccfg.cs = 229; goto _out; 
					_out230: ccfg.cs = 230; goto _out; 
					_out231: ccfg.cs = 231; goto _out; 
					_out232: ccfg.cs = 232; goto _out; 
					_out233: ccfg.cs = 233; goto _out; 
					_out234: ccfg.cs = 234; goto _out; 
					_out235: ccfg.cs = 235; goto _out; 
					_out236: ccfg.cs = 236; goto _out; 
					_out237: ccfg.cs = 237; goto _out; 
					_out238: ccfg.cs = 238; goto _out; 
					_out239: ccfg.cs = 239; goto _out; 
					_out240: ccfg.cs = 240; goto _out; 
					_out241: ccfg.cs = 241; goto _out; 
					_out242: ccfg.cs = 242; goto _out; 
					_out243: ccfg.cs = 243; goto _out; 
					_out244: ccfg.cs = 244; goto _out; 
					_out245: ccfg.cs = 245; goto _out; 
					_out246: ccfg.cs = 246; goto _out; 
					_out247: ccfg.cs = 247; goto _out; 
					_out248: ccfg.cs = 248; goto _out; 
					_out249: ccfg.cs = 249; goto _out; 
					_out250: ccfg.cs = 250; goto _out; 
					_out251: ccfg.cs = 251; goto _out; 
					_out252: ccfg.cs = 252; goto _out; 
					_out253: ccfg.cs = 253; goto _out; 
					_out254: ccfg.cs = 254; goto _out; 
					_out255: ccfg.cs = 255; goto _out; 
					_out256: ccfg.cs = 256; goto _out; 
					_out257: ccfg.cs = 257; goto _out; 
					_out258: ccfg.cs = 258; goto _out; 
					_out259: ccfg.cs = 259; goto _out; 
					_out260: ccfg.cs = 260; goto _out; 
					_out261: ccfg.cs = 261; goto _out; 
					_out262: ccfg.cs = 262; goto _out; 
					_out263: ccfg.cs = 263; goto _out; 
					_out264: ccfg.cs = 264; goto _out; 
					_out265: ccfg.cs = 265; goto _out; 
					_out266: ccfg.cs = 266; goto _out; 
					_out267: ccfg.cs = 267; goto _out; 
					_out268: ccfg.cs = 268; goto _out; 
					_out269: ccfg.cs = 269; goto _out; 
					_out270: ccfg.cs = 270; goto _out; 
					_out271: ccfg.cs = 271; goto _out; 
					_out272: ccfg.cs = 272; goto _out; 
					_out273: ccfg.cs = 273; goto _out; 
					_out274: ccfg.cs = 274; goto _out; 
					_out275: ccfg.cs = 275; goto _out; 
					_out276: ccfg.cs = 276; goto _out; 
					_out277: ccfg.cs = 277; goto _out; 
					_out278: ccfg.cs = 278; goto _out; 
					_out279: ccfg.cs = 279; goto _out; 
					_out280: ccfg.cs = 280; goto _out; 
					_out281: ccfg.cs = 281; goto _out; 
					_out282: ccfg.cs = 282; goto _out; 
					_out283: ccfg.cs = 283; goto _out; 
					_out284: ccfg.cs = 284; goto _out; 
					_out285: ccfg.cs = 285; goto _out; 
					_out286: ccfg.cs = 286; goto _out; 
					_out287: ccfg.cs = 287; goto _out; 
					_out288: ccfg.cs = 288; goto _out; 
					_out289: ccfg.cs = 289; goto _out; 
					_out290: ccfg.cs = 290; goto _out; 
					_out: {}
				}
				
#line 253 "cfg.rl"
				
				
				if (ccfg.cs == file_cfg_error)
					suicide("error parsing config file line %zu: malformed", linenum);
				if (ccfg.cs < file_cfg_first_final)
					suicide("error parsing config file line %zu: incomplete", linenum);
				lstart = lend + 1;
			}
		}
		if (reached_eof)
			break;
		if (!consumed && lend >= sizeof l - 1)
			suicide("Line %zu in config file '%s' is too long: %zu > %zu.",
		linenum, fname, lend, sizeof l - 1);
		
		if (consumed + 1 > lc) suicide("lc[%zu] - consumed[%zu] would underflow", lc, lend);
			if (consumed) {
			memmove(l, l + consumed + 1, lc - consumed - 1);
			lc -= consumed + 1;
		}
	}
	close(fd);
}


#line 323 "cfg.rl"



#line 5929 "cfg.c"
static const int cmd_cfg_start = 248;
static const int cmd_cfg_first_final = 248;
static const int cmd_cfg_error = 0;

static const int cmd_cfg_en_main = 248;


#line 325 "cfg.rl"


void parse_cmdline(int argc, char *argv[])
{
	char argb[8192];
	size_t argbl = 0;
	for (size_t i = 1; i < (size_t)argc; ++i) {
		ssize_t snl;
		if (i > 1)
			snl = snprintf(argb + argbl, sizeof argb - argbl, "%c%s",
		0, argv[i]);
		else
			snl = snprintf(argb + argbl, sizeof argb - argbl, "%s", argv[i]);
		if (snl < 0 || (size_t)snl > sizeof argb)
			suicide("error parsing command line option: option too long");
		argbl += (size_t)snl;
	}
	if (argbl == 0)
		return;
	struct cfgparse ccfg;
	memset(&ccfg, 0, sizeof ccfg);
	const char *p = argb;
	const char *pe = argb + argbl + 1;
	const char *eof = pe;
	
	
#line 5964 "cfg.c"
	{
		ccfg.cs = (int)cmd_cfg_start;
	}
	
#line 350 "cfg.rl"
	
	
#line 5972 "cfg.c"
	{
		switch ( ccfg.cs ) {
			case 248:
			goto st_case_248;
			case 0:
			goto st_case_0;
			case 1:
			goto st_case_1;
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
			case 249:
			goto st_case_249;
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
			case 126:
			goto st_case_126;
			case 127:
			goto st_case_127;
			case 128:
			goto st_case_128;
			case 129:
			goto st_case_129;
			case 130:
			goto st_case_130;
			case 131:
			goto st_case_131;
			case 132:
			goto st_case_132;
			case 133:
			goto st_case_133;
			case 134:
			goto st_case_134;
			case 135:
			goto st_case_135;
			case 136:
			goto st_case_136;
			case 137:
			goto st_case_137;
			case 138:
			goto st_case_138;
			case 139:
			goto st_case_139;
			case 140:
			goto st_case_140;
			case 141:
			goto st_case_141;
			case 142:
			goto st_case_142;
			case 143:
			goto st_case_143;
			case 144:
			goto st_case_144;
			case 145:
			goto st_case_145;
			case 146:
			goto st_case_146;
			case 147:
			goto st_case_147;
			case 148:
			goto st_case_148;
			case 149:
			goto st_case_149;
			case 150:
			goto st_case_150;
			case 151:
			goto st_case_151;
			case 152:
			goto st_case_152;
			case 153:
			goto st_case_153;
			case 154:
			goto st_case_154;
			case 155:
			goto st_case_155;
			case 156:
			goto st_case_156;
			case 157:
			goto st_case_157;
			case 158:
			goto st_case_158;
			case 159:
			goto st_case_159;
			case 160:
			goto st_case_160;
			case 161:
			goto st_case_161;
			case 162:
			goto st_case_162;
			case 163:
			goto st_case_163;
			case 164:
			goto st_case_164;
			case 165:
			goto st_case_165;
			case 166:
			goto st_case_166;
			case 167:
			goto st_case_167;
			case 168:
			goto st_case_168;
			case 169:
			goto st_case_169;
			case 170:
			goto st_case_170;
			case 171:
			goto st_case_171;
			case 172:
			goto st_case_172;
			case 173:
			goto st_case_173;
			case 174:
			goto st_case_174;
			case 175:
			goto st_case_175;
			case 176:
			goto st_case_176;
			case 177:
			goto st_case_177;
			case 178:
			goto st_case_178;
			case 179:
			goto st_case_179;
			case 180:
			goto st_case_180;
			case 181:
			goto st_case_181;
			case 182:
			goto st_case_182;
			case 183:
			goto st_case_183;
			case 184:
			goto st_case_184;
			case 185:
			goto st_case_185;
			case 186:
			goto st_case_186;
			case 187:
			goto st_case_187;
			case 188:
			goto st_case_188;
			case 189:
			goto st_case_189;
			case 190:
			goto st_case_190;
			case 191:
			goto st_case_191;
			case 192:
			goto st_case_192;
			case 193:
			goto st_case_193;
			case 194:
			goto st_case_194;
			case 195:
			goto st_case_195;
			case 196:
			goto st_case_196;
			case 197:
			goto st_case_197;
			case 198:
			goto st_case_198;
			case 199:
			goto st_case_199;
			case 200:
			goto st_case_200;
			case 201:
			goto st_case_201;
			case 202:
			goto st_case_202;
			case 203:
			goto st_case_203;
			case 204:
			goto st_case_204;
			case 205:
			goto st_case_205;
			case 206:
			goto st_case_206;
			case 207:
			goto st_case_207;
			case 208:
			goto st_case_208;
			case 209:
			goto st_case_209;
			case 210:
			goto st_case_210;
			case 211:
			goto st_case_211;
			case 212:
			goto st_case_212;
			case 213:
			goto st_case_213;
			case 214:
			goto st_case_214;
			case 215:
			goto st_case_215;
			case 216:
			goto st_case_216;
			case 217:
			goto st_case_217;
			case 218:
			goto st_case_218;
			case 219:
			goto st_case_219;
			case 220:
			goto st_case_220;
			case 221:
			goto st_case_221;
			case 222:
			goto st_case_222;
			case 223:
			goto st_case_223;
			case 224:
			goto st_case_224;
			case 225:
			goto st_case_225;
			case 226:
			goto st_case_226;
			case 227:
			goto st_case_227;
			case 228:
			goto st_case_228;
			case 229:
			goto st_case_229;
			case 230:
			goto st_case_230;
			case 231:
			goto st_case_231;
			case 232:
			goto st_case_232;
			case 233:
			goto st_case_233;
			case 234:
			goto st_case_234;
			case 235:
			goto st_case_235;
			case 236:
			goto st_case_236;
			case 237:
			goto st_case_237;
			case 238:
			goto st_case_238;
			case 239:
			goto st_case_239;
			case 240:
			goto st_case_240;
			case 241:
			goto st_case_241;
			case 242:
			goto st_case_242;
			case 243:
			goto st_case_243;
			case 244:
			goto st_case_244;
			case 245:
			goto st_case_245;
			case 246:
			goto st_case_246;
			case 247:
			goto st_case_247;
		}
		_ctr58:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6484 "cfg.c"
		
		{
#line 127 "cfg.rl"
			
			int t = atoi(ccfg.buf);
			arp_probe_max = t;
			if (arp_probe_min > arp_probe_max) {
				t = arp_probe_max;
				arp_probe_max = arp_probe_min;
				arp_probe_min = t;
			}
		}
		
#line 6498 "cfg.c"
		
		goto _st248;
		_ctr63:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6509 "cfg.c"
		
		{
#line 118 "cfg.rl"
			
			int t = atoi(ccfg.buf);
			arp_probe_min = t;
			if (arp_probe_min > arp_probe_max) {
				t = arp_probe_max;
				arp_probe_max = arp_probe_min;
				arp_probe_min = t;
			}
		}
		
#line 6523 "cfg.c"
		
		goto _st248;
		_ctr69:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6534 "cfg.c"
		
		{
#line 113 "cfg.rl"
			
			int t = atoi(ccfg.buf);
			if (t >= 0)
			arp_probe_num = t;
		}
		
#line 6544 "cfg.c"
		
		goto _st248;
		_ctr76:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6555 "cfg.c"
		
		{
#line 108 "cfg.rl"
			
			int t = atoi(ccfg.buf);
			if (t >= 0)
			arp_probe_wait = t;
		}
		
#line 6565 "cfg.c"
		
		goto _st248;
		_ctr87:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6576 "cfg.c"
		
		{
#line 89 "cfg.rl"
			
			copy_cmdarg(chroot_dir, ccfg.buf, sizeof chroot_dir, "chroot");
		}
		
#line 6584 "cfg.c"
		
		goto _st248;
		_ctr97:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6595 "cfg.c"
		
		{
#line 57 "cfg.rl"
			get_clientid_string(ccfg.buf, ccfg.buflen); }
		
#line 6601 "cfg.c"
		
		goto _st248;
		_ctr105:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6612 "cfg.c"
		
		{
#line 282 "cfg.rl"
			parse_cfgfile(ccfg.buf); }
		
#line 6618 "cfg.c"
		
		goto _st248;
		_ctr133:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6629 "cfg.c"
		
		{
#line 136 "cfg.rl"
			
			char *q;
			long mt = strtol(ccfg.buf, &q, 10);
			if (q == ccfg.buf)
			suicide("gw-metric arg '%s' isn't a valid number", ccfg.buf);
			if (mt > INT_MAX)
			suicide("gw-metric arg '%s' is too large", ccfg.buf);
			if (mt < 0)
			mt = 0;
			client_config.metric = (int)mt;
		}
		
#line 6645 "cfg.c"
		
		goto _st248;
		_ctr137:
		{
#line 167 "cfg.rl"
			show_usage(); exit(EXIT_SUCCESS); }
		
#line 6653 "cfg.c"
		
		goto _st248;
		_ctr147:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6664 "cfg.c"
		
		{
#line 58 "cfg.rl"
			
			copy_cmdarg(client_config.hostname, ccfg.buf,
			sizeof client_config.hostname, "hostname");
		}
		
#line 6673 "cfg.c"
		
		goto _st248;
		_ctr160:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6684 "cfg.c"
		
		{
#line 81 "cfg.rl"
			
			if (nk_uidgidbyname(ccfg.buf, &ifch_uid, &ifch_gid))
			suicide("invalid ifch user '%s' specified", ccfg.buf);
		}
		
#line 6693 "cfg.c"
		
		goto _st248;
		_ctr171:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6704 "cfg.c"
		
		{
#line 62 "cfg.rl"
			
			copy_cmdarg(client_config.interface, ccfg.buf,
			sizeof client_config.interface, "interface");
		}
		
#line 6713 "cfg.c"
		
		goto _st248;
		_ctr201:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6724 "cfg.c"
		
		{
#line 72 "cfg.rl"
			set_client_addr(ccfg.buf); }
		
#line 6730 "cfg.c"
		
		goto _st248;
		_ctr213:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6741 "cfg.c"
		
		{
#line 147 "cfg.rl"
			
			copy_cmdarg(resolv_conf_d, ccfg.buf, sizeof resolv_conf_d,
			"resolv-conf");
		}
		
#line 6750 "cfg.c"
		
		goto _st248;
		_ctr225:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6761 "cfg.c"
		
		{
#line 157 "cfg.rl"
			
			uint32_t t = (uint32_t)atoi(ccfg.buf);
			client_config.rfkillIdx = t;
			client_config.enable_rfkill = true;
		}
		
#line 6771 "cfg.c"
		
		goto _st248;
		_ctr241:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6782 "cfg.c"
		
		{
#line 162 "cfg.rl"
			
			client_config.s6_notify_fd = atoi(ccfg.buf);
			client_config.enable_s6_notify = true;
		}
		
#line 6791 "cfg.c"
		
		goto _st248;
		_ctr254:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6802 "cfg.c"
		
		{
#line 95 "cfg.rl"
			
			copy_cmdarg(script_file, ccfg.buf, sizeof script_file, "script-file");
		}
		
#line 6810 "cfg.c"
		
		goto _st248;
		_ctr279:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6821 "cfg.c"
		
		{
#line 85 "cfg.rl"
			
			if (nk_uidgidbyname(ccfg.buf, &sockd_uid, &sockd_gid))
			suicide("invalid sockd user '%s' specified", ccfg.buf);
		}
		
#line 6830 "cfg.c"
		
		goto _st248;
		_ctr290:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6841 "cfg.c"
		
		{
#line 92 "cfg.rl"
			
			copy_cmdarg(state_dir, ccfg.buf, sizeof state_dir, "state-dir");
		}
		
#line 6849 "cfg.c"
		
		goto _st248;
		_ctr297:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6860 "cfg.c"
		
		{
#line 77 "cfg.rl"
			
			if (nk_uidgidbyname(ccfg.buf, &ndhc_uid, &ndhc_gid))
			suicide("invalid ndhc user '%s' specified", ccfg.buf);
		}
		
#line 6869 "cfg.c"
		
		goto _st248;
		_ctr309:
		{
#line 50 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf)
			ccfg.buf[ccfg.buflen] = 0;
		}
		
#line 6880 "cfg.c"
		
		{
#line 73 "cfg.rl"
			
			copy_cmdarg(client_config.vendor, ccfg.buf,
			sizeof client_config.vendor, "vendorid");
		}
		
#line 6889 "cfg.c"
		
		goto _st248;
		_ctr313:
		{
#line 166 "cfg.rl"
			print_version(); exit(EXIT_SUCCESS); }
		
#line 6897 "cfg.c"
		
		goto _st248;
		_st248:
		if ( p == eof )
			goto _out248;
		p+= 1;
		st_case_248:
		if ( p == pe && p != eof )
			goto _out248;
		if ( p == eof ) {
			goto _st248;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st1;
			}
			goto _st0;
		}
		_st0:
		if ( p == eof )
			goto _out0;
		st_case_0:
		goto _out0;
		_ctr316:
		{
#line 283 "cfg.rl"
			ccfg.ternary = 1; }
		
#line 6925 "cfg.c"
		
		goto _st1;
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
			switch( ( (*( p))) ) {
				case 45: {
					goto _st2;
				}
				case 63: {
					goto _st88;
				}
				case 67: {
					goto _st38;
				}
				case 68: {
					goto _st214;
				}
				case 72: {
					goto _st73;
				}
				case 73: {
					goto _st47;
				}
				case 75: {
					goto _st166;
				}
				case 77: {
					goto _st15;
				}
				case 78: {
					goto _st177;
				}
				case 82: {
					goto _st155;
				}
				case 83: {
					goto _st205;
				}
				case 85: {
					goto _st106;
				}
				case 86: {
					goto _st240;
				}
				case 87: {
					goto _st24;
				}
				case 88: {
					goto _st189;
				}
				case 99: {
					goto _st54;
				}
				case 100: {
					goto _st139;
				}
				case 104: {
					goto _st95;
				}
				case 105: {
					goto _st116;
				}
				case 109: {
					goto _st19;
				}
				case 110: {
					goto _st121;
				}
				case 114: {
					goto _st144;
				}
				case 115: {
					goto _st224;
				}
				case 116: {
					goto _st82;
				}
				case 117: {
					goto _st230;
				}
				case 118: {
					goto _st247;
				}
				case 119: {
					goto _st30;
				}
			}
			goto _st0;
		}
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
			switch( ( (*( p))) ) {
				case 97: {
					goto _st3;
				}
				case 99: {
					goto _st33;
				}
				case 100: {
					goto _st57;
				}
				case 103: {
					goto _st74;
				}
				case 104: {
					goto _st85;
				}
				case 105: {
					goto _st98;
				}
				case 110: {
					goto _st119;
				}
				case 114: {
					goto _st122;
				}
				case 115: {
					goto _st169;
				}
				case 117: {
					goto _st227;
				}
				case 118: {
					goto _st233;
				}
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
			if ( ( (*( p))) == 114 ) {
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
			if ( ( (*( p))) == 112 ) {
				goto _st5;
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
			if ( ( (*( p))) == 45 ) {
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
			if ( ( (*( p))) == 112 ) {
				goto _st7;
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
			if ( ( (*( p))) == 114 ) {
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
			if ( ( (*( p))) == 111 ) {
				goto _st9;
			}
			goto _st0;
		}
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
			if ( ( (*( p))) == 98 ) {
				goto _st10;
			}
			goto _st0;
		}
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
			if ( ( (*( p))) == 101 ) {
				goto _st11;
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
			if ( ( (*( p))) == 45 ) {
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
			switch( ( (*( p))) ) {
				case 109: {
					goto _st13;
				}
				case 110: {
					goto _st22;
				}
				case 119: {
					goto _st27;
				}
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
			switch( ( (*( p))) ) {
				case 97: {
					goto _st14;
				}
				case 105: {
					goto _st18;
				}
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
			if ( ( (*( p))) == 120 ) {
				goto _st15;
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
			if ( ( (*( p))) == 0 ) {
				goto _st16;
			}
			goto _st0;
		}
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
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr55;
		}
		_ctr55:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 7302 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7313 "cfg.c"
		
		goto _st17;
		_ctr57:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7326 "cfg.c"
		
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
			if ( ( (*( p))) == 0 ) {
				goto _ctr58;
			}
			goto _ctr57;
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
			if ( ( (*( p))) == 110 ) {
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
			if ( ( (*( p))) == 0 ) {
				goto _st20;
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
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr60;
		}
		_ctr60:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 7398 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7409 "cfg.c"
		
		goto _st21;
		_ctr62:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7422 "cfg.c"
		
		goto _st21;
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
			if ( ( (*( p))) == 0 ) {
				goto _ctr63;
			}
			goto _ctr62;
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
			if ( ( (*( p))) == 117 ) {
				goto _st23;
			}
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
			if ( ( (*( p))) == 109 ) {
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
			if ( ( (*( p))) == 0 ) {
				goto _st25;
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
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr66;
		}
		_ctr66:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 7509 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7520 "cfg.c"
		
		goto _st26;
		_ctr68:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7533 "cfg.c"
		
		goto _st26;
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
			if ( ( (*( p))) == 0 ) {
				goto _ctr69;
			}
			goto _ctr68;
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
			if ( ( (*( p))) == 97 ) {
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
			if ( ( (*( p))) == 105 ) {
				goto _st29;
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
			if ( ( (*( p))) == 116 ) {
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
			if ( ( (*( p))) == 0 ) {
				goto _st31;
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
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr73;
		}
		_ctr73:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 7635 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7646 "cfg.c"
		
		goto _st32;
		_ctr75:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7659 "cfg.c"
		
		goto _st32;
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
			if ( ( (*( p))) == 0 ) {
				goto _ctr76;
			}
			goto _ctr75;
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
			switch( ( (*( p))) ) {
				case 104: {
					goto _st34;
				}
				case 108: {
					goto _st41;
				}
				case 111: {
					goto _st50;
				}
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
			if ( ( (*( p))) == 114 ) {
				goto _st35;
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
			if ( ( (*( p))) == 111 ) {
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
			if ( ( (*( p))) == 111 ) {
				goto _st37;
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
			if ( ( (*( p))) == 116 ) {
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
			if ( ( (*( p))) == 0 ) {
				goto _st39;
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
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr84;
		}
		_ctr84:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 7799 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7810 "cfg.c"
		
		goto _st40;
		_ctr86:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7823 "cfg.c"
		
		goto _st40;
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
			if ( ( (*( p))) == 0 ) {
				goto _ctr87;
			}
			goto _ctr86;
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
			if ( ( (*( p))) == 105 ) {
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
			if ( ( (*( p))) == 101 ) {
				goto _st43;
			}
			goto _st0;
		}
		_st43:
		if ( p == eof )
			goto _out43;
		p+= 1;
		st_case_43:
		if ( p == pe && p != eof )
			goto _out43;
		if ( p == eof ) {
			goto _st43;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st44;
			}
			goto _st0;
		}
		_st44:
		if ( p == eof )
			goto _out44;
		p+= 1;
		st_case_44:
		if ( p == pe && p != eof )
			goto _out44;
		if ( p == eof ) {
			goto _st44;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st45;
			}
			goto _st0;
		}
		_st45:
		if ( p == eof )
			goto _out45;
		p+= 1;
		st_case_45:
		if ( p == pe && p != eof )
			goto _out45;
		if ( p == eof ) {
			goto _st45;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st46;
			}
			goto _st0;
		}
		_st46:
		if ( p == eof )
			goto _out46;
		p+= 1;
		st_case_46:
		if ( p == pe && p != eof )
			goto _out46;
		if ( p == eof ) {
			goto _st46;}
		else {
			if ( ( (*( p))) == 100 ) {
				goto _st47;
			}
			goto _st0;
		}
		_st47:
		if ( p == eof )
			goto _out47;
		p+= 1;
		st_case_47:
		if ( p == pe && p != eof )
			goto _out47;
		if ( p == eof ) {
			goto _st47;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st48;
			}
			goto _st0;
		}
		_st48:
		if ( p == eof )
			goto _out48;
		p+= 1;
		st_case_48:
		if ( p == pe && p != eof )
			goto _out48;
		if ( p == eof ) {
			goto _st48;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr94;
		}
		_ctr94:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 7970 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7981 "cfg.c"
		
		goto _st49;
		_ctr96:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 7994 "cfg.c"
		
		goto _st49;
		_st49:
		if ( p == eof )
			goto _out49;
		p+= 1;
		st_case_49:
		if ( p == pe && p != eof )
			goto _out49;
		if ( p == eof ) {
			goto _st49;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr97;
			}
			goto _ctr96;
		}
		_st50:
		if ( p == eof )
			goto _out50;
		p+= 1;
		st_case_50:
		if ( p == pe && p != eof )
			goto _out50;
		if ( p == eof ) {
			goto _st50;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st51;
			}
			goto _st0;
		}
		_st51:
		if ( p == eof )
			goto _out51;
		p+= 1;
		st_case_51:
		if ( p == pe && p != eof )
			goto _out51;
		if ( p == eof ) {
			goto _st51;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st52;
			}
			goto _st0;
		}
		_st52:
		if ( p == eof )
			goto _out52;
		p+= 1;
		st_case_52:
		if ( p == pe && p != eof )
			goto _out52;
		if ( p == eof ) {
			goto _st52;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st53;
			}
			goto _st0;
		}
		_st53:
		if ( p == eof )
			goto _out53;
		p+= 1;
		st_case_53:
		if ( p == pe && p != eof )
			goto _out53;
		if ( p == eof ) {
			goto _st53;}
		else {
			if ( ( (*( p))) == 103 ) {
				goto _st54;
			}
			goto _st0;
		}
		_st54:
		if ( p == eof )
			goto _out54;
		p+= 1;
		st_case_54:
		if ( p == pe && p != eof )
			goto _out54;
		if ( p == eof ) {
			goto _st54;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st55;
			}
			goto _st0;
		}
		_st55:
		if ( p == eof )
			goto _out55;
		p+= 1;
		st_case_55:
		if ( p == pe && p != eof )
			goto _out55;
		if ( p == eof ) {
			goto _st55;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr102;
		}
		_ctr102:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 8111 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 8122 "cfg.c"
		
		goto _st56;
		_ctr104:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 8135 "cfg.c"
		
		goto _st56;
		_st56:
		if ( p == eof )
			goto _out56;
		p+= 1;
		st_case_56:
		if ( p == pe && p != eof )
			goto _out56;
		if ( p == eof ) {
			goto _st56;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr105;
			}
			goto _ctr104;
		}
		_st57:
		if ( p == eof )
			goto _out57;
		p+= 1;
		st_case_57:
		if ( p == pe && p != eof )
			goto _out57;
		if ( p == eof ) {
			goto _st57;}
		else {
			if ( ( (*( p))) == 104 ) {
				goto _st58;
			}
			goto _st0;
		}
		_st58:
		if ( p == eof )
			goto _out58;
		p+= 1;
		st_case_58:
		if ( p == pe && p != eof )
			goto _out58;
		if ( p == eof ) {
			goto _st58;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st59;
			}
			goto _st0;
		}
		_st59:
		if ( p == eof )
			goto _out59;
		p+= 1;
		st_case_59:
		if ( p == pe && p != eof )
			goto _out59;
		if ( p == eof ) {
			goto _st59;}
		else {
			if ( ( (*( p))) == 112 ) {
				goto _st60;
			}
			goto _st0;
		}
		_st60:
		if ( p == eof )
			goto _out60;
		p+= 1;
		st_case_60:
		if ( p == pe && p != eof )
			goto _out60;
		if ( p == eof ) {
			goto _st60;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st61;
			}
			goto _st0;
		}
		_st61:
		if ( p == eof )
			goto _out61;
		p+= 1;
		st_case_61:
		if ( p == pe && p != eof )
			goto _out61;
		if ( p == eof ) {
			goto _st61;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st62;
			}
			goto _st0;
		}
		_st62:
		if ( p == eof )
			goto _out62;
		p+= 1;
		st_case_62:
		if ( p == pe && p != eof )
			goto _out62;
		if ( p == eof ) {
			goto _st62;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st63;
			}
			goto _st0;
		}
		_st63:
		if ( p == eof )
			goto _out63;
		p+= 1;
		st_case_63:
		if ( p == pe && p != eof )
			goto _out63;
		if ( p == eof ) {
			goto _st63;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st64;
			}
			goto _st0;
		}
		_st64:
		if ( p == eof )
			goto _out64;
		p+= 1;
		st_case_64:
		if ( p == pe && p != eof )
			goto _out64;
		if ( p == eof ) {
			goto _st64;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st65;
			}
			goto _st0;
		}
		_st65:
		if ( p == eof )
			goto _out65;
		p+= 1;
		st_case_65:
		if ( p == pe && p != eof )
			goto _out65;
		if ( p == eof ) {
			goto _st65;}
		else {
			if ( ( (*( p))) == 104 ) {
				goto _st66;
			}
			goto _st0;
		}
		_st66:
		if ( p == eof )
			goto _out66;
		p+= 1;
		st_case_66:
		if ( p == pe && p != eof )
			goto _out66;
		if ( p == eof ) {
			goto _st66;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st67;
			}
			goto _st0;
		}
		_st67:
		if ( p == eof )
			goto _out67;
		p+= 1;
		st_case_67:
		if ( p == pe && p != eof )
			goto _out67;
		if ( p == eof ) {
			goto _st67;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st68;
			}
			goto _st0;
		}
		_st68:
		if ( p == eof )
			goto _out68;
		p+= 1;
		st_case_68:
		if ( p == pe && p != eof )
			goto _out68;
		if ( p == eof ) {
			goto _st68;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st69;
			}
			goto _st0;
		}
		_st69:
		if ( p == eof )
			goto _out69;
		p+= 1;
		st_case_69:
		if ( p == pe && p != eof )
			goto _out69;
		if ( p == eof ) {
			goto _st69;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st70;
			}
			goto _st0;
		}
		_st70:
		if ( p == eof )
			goto _out70;
		p+= 1;
		st_case_70:
		if ( p == pe && p != eof )
			goto _out70;
		if ( p == eof ) {
			goto _st70;}
		else {
			if ( ( (*( p))) == 97 ) {
				goto _st71;
			}
			goto _st0;
		}
		_st71:
		if ( p == eof )
			goto _out71;
		p+= 1;
		st_case_71:
		if ( p == pe && p != eof )
			goto _out71;
		if ( p == eof ) {
			goto _st71;}
		else {
			if ( ( (*( p))) == 109 ) {
				goto _st72;
			}
			goto _st0;
		}
		_st72:
		if ( p == eof )
			goto _out72;
		p+= 1;
		st_case_72:
		if ( p == pe && p != eof )
			goto _out72;
		if ( p == eof ) {
			goto _st72;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st73;
			}
			goto _st0;
		}
		_st73:
		if ( p == eof )
			goto _out73;
		p+= 1;
		st_case_73:
		if ( p == pe && p != eof )
			goto _out73;
		if ( p == eof ) {
			goto _st73;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr121;
			}
			goto _st0;
		}
		_ctr121:
		{
#line 151 "cfg.rl"
			
			switch (ccfg.ternary) {
				case 1: allow_hostname = 1; break;
				case -1: allow_hostname = 0; default: break;
			}
		}
		
#line 8418 "cfg.c"
		
		goto _st249;
		_ctr173:
		{
#line 66 "cfg.rl"
			
			switch (ccfg.ternary) {
				case 1: client_config.abort_if_no_lease = true; break;
				case -1: client_config.abort_if_no_lease = false; default: break;
			}
		}
		
#line 8431 "cfg.c"
		
		goto _st249;
		_ctr193:
		{
#line 102 "cfg.rl"
			
			switch (ccfg.ternary) {
				case 1: set_arp_relentless_def(true); break;
				case -1: set_arp_relentless_def(false); default: break;
			}
		}
		
#line 8444 "cfg.c"
		
		goto _st249;
		_ctr267:
		{
#line 98 "cfg.rl"
			
			log_line("seccomp_enforce option is deprecated; please remove it");
			log_line("In the meanwhile, it is ignored and seccomp is disabled.");
		}
		
#line 8455 "cfg.c"
		
		goto _st249;
		_ctr315:
		{
#line 283 "cfg.rl"
			ccfg.ternary = 1; }
		
#line 8463 "cfg.c"
		
		goto _st249;
		_st249:
		if ( p == eof )
			goto _out249;
		p+= 1;
		st_case_249:
		if ( p == pe && p != eof )
			goto _out249;
		if ( p == eof ) {
			goto _ctr315;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _ctr316;
			}
			goto _st0;
		}
		_st74:
		if ( p == eof )
			goto _out74;
		p+= 1;
		st_case_74:
		if ( p == pe && p != eof )
			goto _out74;
		if ( p == eof ) {
			goto _st74;}
		else {
			if ( ( (*( p))) == 119 ) {
				goto _st75;
			}
			goto _st0;
		}
		_st75:
		if ( p == eof )
			goto _out75;
		p+= 1;
		st_case_75:
		if ( p == pe && p != eof )
			goto _out75;
		if ( p == eof ) {
			goto _st75;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st76;
			}
			goto _st0;
		}
		_st76:
		if ( p == eof )
			goto _out76;
		p+= 1;
		st_case_76:
		if ( p == pe && p != eof )
			goto _out76;
		if ( p == eof ) {
			goto _st76;}
		else {
			if ( ( (*( p))) == 109 ) {
				goto _st77;
			}
			goto _st0;
		}
		_st77:
		if ( p == eof )
			goto _out77;
		p+= 1;
		st_case_77:
		if ( p == pe && p != eof )
			goto _out77;
		if ( p == eof ) {
			goto _st77;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st78;
			}
			goto _st0;
		}
		_st78:
		if ( p == eof )
			goto _out78;
		p+= 1;
		st_case_78:
		if ( p == pe && p != eof )
			goto _out78;
		if ( p == eof ) {
			goto _st78;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st79;
			}
			goto _st0;
		}
		_st79:
		if ( p == eof )
			goto _out79;
		p+= 1;
		st_case_79:
		if ( p == pe && p != eof )
			goto _out79;
		if ( p == eof ) {
			goto _st79;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st80;
			}
			goto _st0;
		}
		_st80:
		if ( p == eof )
			goto _out80;
		p+= 1;
		st_case_80:
		if ( p == pe && p != eof )
			goto _out80;
		if ( p == eof ) {
			goto _st80;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st81;
			}
			goto _st0;
		}
		_st81:
		if ( p == eof )
			goto _out81;
		p+= 1;
		st_case_81:
		if ( p == pe && p != eof )
			goto _out81;
		if ( p == eof ) {
			goto _st81;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st82;
			}
			goto _st0;
		}
		_st82:
		if ( p == eof )
			goto _out82;
		p+= 1;
		st_case_82:
		if ( p == pe && p != eof )
			goto _out82;
		if ( p == eof ) {
			goto _st82;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st83;
			}
			goto _st0;
		}
		_st83:
		if ( p == eof )
			goto _out83;
		p+= 1;
		st_case_83:
		if ( p == pe && p != eof )
			goto _out83;
		if ( p == eof ) {
			goto _st83;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr130;
		}
		_ctr130:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 8640 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 8651 "cfg.c"
		
		goto _st84;
		_ctr132:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 8664 "cfg.c"
		
		goto _st84;
		_st84:
		if ( p == eof )
			goto _out84;
		p+= 1;
		st_case_84:
		if ( p == pe && p != eof )
			goto _out84;
		if ( p == eof ) {
			goto _st84;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr133;
			}
			goto _ctr132;
		}
		_st85:
		if ( p == eof )
			goto _out85;
		p+= 1;
		st_case_85:
		if ( p == pe && p != eof )
			goto _out85;
		if ( p == eof ) {
			goto _st85;}
		else {
			switch( ( (*( p))) ) {
				case 101: {
					goto _st86;
				}
				case 111: {
					goto _st89;
				}
			}
			goto _st0;
		}
		_st86:
		if ( p == eof )
			goto _out86;
		p+= 1;
		st_case_86:
		if ( p == pe && p != eof )
			goto _out86;
		if ( p == eof ) {
			goto _st86;}
		else {
			if ( ( (*( p))) == 108 ) {
				goto _st87;
			}
			goto _st0;
		}
		_st87:
		if ( p == eof )
			goto _out87;
		p+= 1;
		st_case_87:
		if ( p == pe && p != eof )
			goto _out87;
		if ( p == eof ) {
			goto _st87;}
		else {
			if ( ( (*( p))) == 112 ) {
				goto _st88;
			}
			goto _st0;
		}
		_st88:
		if ( p == eof )
			goto _out88;
		p+= 1;
		st_case_88:
		if ( p == pe && p != eof )
			goto _out88;
		if ( p == eof ) {
			goto _st88;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr137;
			}
			goto _st0;
		}
		_st89:
		if ( p == eof )
			goto _out89;
		p+= 1;
		st_case_89:
		if ( p == pe && p != eof )
			goto _out89;
		if ( p == eof ) {
			goto _st89;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st90;
			}
			goto _st0;
		}
		_st90:
		if ( p == eof )
			goto _out90;
		p+= 1;
		st_case_90:
		if ( p == pe && p != eof )
			goto _out90;
		if ( p == eof ) {
			goto _st90;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st91;
			}
			goto _st0;
		}
		_st91:
		if ( p == eof )
			goto _out91;
		p+= 1;
		st_case_91:
		if ( p == pe && p != eof )
			goto _out91;
		if ( p == eof ) {
			goto _st91;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st92;
			}
			goto _st0;
		}
		_st92:
		if ( p == eof )
			goto _out92;
		p+= 1;
		st_case_92:
		if ( p == pe && p != eof )
			goto _out92;
		if ( p == eof ) {
			goto _st92;}
		else {
			if ( ( (*( p))) == 97 ) {
				goto _st93;
			}
			goto _st0;
		}
		_st93:
		if ( p == eof )
			goto _out93;
		p+= 1;
		st_case_93:
		if ( p == pe && p != eof )
			goto _out93;
		if ( p == eof ) {
			goto _st93;}
		else {
			if ( ( (*( p))) == 109 ) {
				goto _st94;
			}
			goto _st0;
		}
		_st94:
		if ( p == eof )
			goto _out94;
		p+= 1;
		st_case_94:
		if ( p == pe && p != eof )
			goto _out94;
		if ( p == eof ) {
			goto _st94;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st95;
			}
			goto _st0;
		}
		_st95:
		if ( p == eof )
			goto _out95;
		p+= 1;
		st_case_95:
		if ( p == pe && p != eof )
			goto _out95;
		if ( p == eof ) {
			goto _st95;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st96;
			}
			goto _st0;
		}
		_st96:
		if ( p == eof )
			goto _out96;
		p+= 1;
		st_case_96:
		if ( p == pe && p != eof )
			goto _out96;
		if ( p == eof ) {
			goto _st96;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr144;
		}
		_ctr144:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 8876 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 8887 "cfg.c"
		
		goto _st97;
		_ctr146:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 8900 "cfg.c"
		
		goto _st97;
		_st97:
		if ( p == eof )
			goto _out97;
		p+= 1;
		st_case_97:
		if ( p == pe && p != eof )
			goto _out97;
		if ( p == eof ) {
			goto _st97;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr147;
			}
			goto _ctr146;
		}
		_st98:
		if ( p == eof )
			goto _out98;
		p+= 1;
		st_case_98:
		if ( p == pe && p != eof )
			goto _out98;
		if ( p == eof ) {
			goto _st98;}
		else {
			switch( ( (*( p))) ) {
				case 102: {
					goto _st99;
				}
				case 110: {
					goto _st109;
				}
			}
			goto _st0;
		}
		_st99:
		if ( p == eof )
			goto _out99;
		p+= 1;
		st_case_99:
		if ( p == pe && p != eof )
			goto _out99;
		if ( p == eof ) {
			goto _st99;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st100;
			}
			goto _st0;
		}
		_st100:
		if ( p == eof )
			goto _out100;
		p+= 1;
		st_case_100:
		if ( p == pe && p != eof )
			goto _out100;
		if ( p == eof ) {
			goto _st100;}
		else {
			if ( ( (*( p))) == 104 ) {
				goto _st101;
			}
			goto _st0;
		}
		_st101:
		if ( p == eof )
			goto _out101;
		p+= 1;
		st_case_101:
		if ( p == pe && p != eof )
			goto _out101;
		if ( p == eof ) {
			goto _st101;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st102;
			}
			goto _st0;
		}
		_st102:
		if ( p == eof )
			goto _out102;
		p+= 1;
		st_case_102:
		if ( p == pe && p != eof )
			goto _out102;
		if ( p == eof ) {
			goto _st102;}
		else {
			if ( ( (*( p))) == 117 ) {
				goto _st103;
			}
			goto _st0;
		}
		_st103:
		if ( p == eof )
			goto _out103;
		p+= 1;
		st_case_103:
		if ( p == pe && p != eof )
			goto _out103;
		if ( p == eof ) {
			goto _st103;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st104;
			}
			goto _st0;
		}
		_st104:
		if ( p == eof )
			goto _out104;
		p+= 1;
		st_case_104:
		if ( p == pe && p != eof )
			goto _out104;
		if ( p == eof ) {
			goto _st104;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st105;
			}
			goto _st0;
		}
		_st105:
		if ( p == eof )
			goto _out105;
		p+= 1;
		st_case_105:
		if ( p == pe && p != eof )
			goto _out105;
		if ( p == eof ) {
			goto _st105;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st106;
			}
			goto _st0;
		}
		_st106:
		if ( p == eof )
			goto _out106;
		p+= 1;
		st_case_106:
		if ( p == pe && p != eof )
			goto _out106;
		if ( p == eof ) {
			goto _st106;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st107;
			}
			goto _st0;
		}
		_st107:
		if ( p == eof )
			goto _out107;
		p+= 1;
		st_case_107:
		if ( p == pe && p != eof )
			goto _out107;
		if ( p == eof ) {
			goto _st107;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr157;
		}
		_ctr157:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 9082 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 9093 "cfg.c"
		
		goto _st108;
		_ctr159:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 9106 "cfg.c"
		
		goto _st108;
		_st108:
		if ( p == eof )
			goto _out108;
		p+= 1;
		st_case_108:
		if ( p == pe && p != eof )
			goto _out108;
		if ( p == eof ) {
			goto _st108;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr160;
			}
			goto _ctr159;
		}
		_st109:
		if ( p == eof )
			goto _out109;
		p+= 1;
		st_case_109:
		if ( p == pe && p != eof )
			goto _out109;
		if ( p == eof ) {
			goto _st109;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st110;
			}
			goto _st0;
		}
		_st110:
		if ( p == eof )
			goto _out110;
		p+= 1;
		st_case_110:
		if ( p == pe && p != eof )
			goto _out110;
		if ( p == eof ) {
			goto _st110;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st111;
			}
			goto _st0;
		}
		_st111:
		if ( p == eof )
			goto _out111;
		p+= 1;
		st_case_111:
		if ( p == pe && p != eof )
			goto _out111;
		if ( p == eof ) {
			goto _st111;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st112;
			}
			goto _st0;
		}
		_st112:
		if ( p == eof )
			goto _out112;
		p+= 1;
		st_case_112:
		if ( p == pe && p != eof )
			goto _out112;
		if ( p == eof ) {
			goto _st112;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st113;
			}
			goto _st0;
		}
		_st113:
		if ( p == eof )
			goto _out113;
		p+= 1;
		st_case_113:
		if ( p == pe && p != eof )
			goto _out113;
		if ( p == eof ) {
			goto _st113;}
		else {
			if ( ( (*( p))) == 97 ) {
				goto _st114;
			}
			goto _st0;
		}
		_st114:
		if ( p == eof )
			goto _out114;
		p+= 1;
		st_case_114:
		if ( p == pe && p != eof )
			goto _out114;
		if ( p == eof ) {
			goto _st114;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st115;
			}
			goto _st0;
		}
		_st115:
		if ( p == eof )
			goto _out115;
		p+= 1;
		st_case_115:
		if ( p == pe && p != eof )
			goto _out115;
		if ( p == eof ) {
			goto _st115;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st116;
			}
			goto _st0;
		}
		_st116:
		if ( p == eof )
			goto _out116;
		p+= 1;
		st_case_116:
		if ( p == pe && p != eof )
			goto _out116;
		if ( p == eof ) {
			goto _st116;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st117;
			}
			goto _st0;
		}
		_st117:
		if ( p == eof )
			goto _out117;
		p+= 1;
		st_case_117:
		if ( p == pe && p != eof )
			goto _out117;
		if ( p == eof ) {
			goto _st117;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr168;
		}
		_ctr168:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 9268 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 9279 "cfg.c"
		
		goto _st118;
		_ctr170:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 9292 "cfg.c"
		
		goto _st118;
		_st118:
		if ( p == eof )
			goto _out118;
		p+= 1;
		st_case_118:
		if ( p == pe && p != eof )
			goto _out118;
		if ( p == eof ) {
			goto _st118;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr171;
			}
			goto _ctr170;
		}
		_st119:
		if ( p == eof )
			goto _out119;
		p+= 1;
		st_case_119:
		if ( p == pe && p != eof )
			goto _out119;
		if ( p == eof ) {
			goto _st119;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st120;
			}
			goto _st0;
		}
		_st120:
		if ( p == eof )
			goto _out120;
		p+= 1;
		st_case_120:
		if ( p == pe && p != eof )
			goto _out120;
		if ( p == eof ) {
			goto _st120;}
		else {
			if ( ( (*( p))) == 119 ) {
				goto _st121;
			}
			goto _st0;
		}
		_st121:
		if ( p == eof )
			goto _out121;
		p+= 1;
		st_case_121:
		if ( p == pe && p != eof )
			goto _out121;
		if ( p == eof ) {
			goto _st121;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr173;
			}
			goto _st0;
		}
		_st122:
		if ( p == eof )
			goto _out122;
		p+= 1;
		st_case_122:
		if ( p == pe && p != eof )
			goto _out122;
		if ( p == eof ) {
			goto _st122;}
		else {
			switch( ( (*( p))) ) {
				case 101: {
					goto _st123;
				}
				case 102: {
					goto _st158;
				}
			}
			goto _st0;
		}
		_st123:
		if ( p == eof )
			goto _out123;
		p+= 1;
		st_case_123:
		if ( p == pe && p != eof )
			goto _out123;
		if ( p == eof ) {
			goto _st123;}
		else {
			switch( ( (*( p))) ) {
				case 108: {
					goto _st124;
				}
				case 113: {
					goto _st140;
				}
				case 115: {
					goto _st147;
				}
			}
			goto _st0;
		}
		_st124:
		if ( p == eof )
			goto _out124;
		p+= 1;
		st_case_124:
		if ( p == pe && p != eof )
			goto _out124;
		if ( p == eof ) {
			goto _st124;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st125;
			}
			goto _st0;
		}
		_st125:
		if ( p == eof )
			goto _out125;
		p+= 1;
		st_case_125:
		if ( p == pe && p != eof )
			goto _out125;
		if ( p == eof ) {
			goto _st125;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st126;
			}
			goto _st0;
		}
		_st126:
		if ( p == eof )
			goto _out126;
		p+= 1;
		st_case_126:
		if ( p == pe && p != eof )
			goto _out126;
		if ( p == eof ) {
			goto _st126;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st127;
			}
			goto _st0;
		}
		_st127:
		if ( p == eof )
			goto _out127;
		p+= 1;
		st_case_127:
		if ( p == pe && p != eof )
			goto _out127;
		if ( p == eof ) {
			goto _st127;}
		else {
			if ( ( (*( p))) == 108 ) {
				goto _st128;
			}
			goto _st0;
		}
		_st128:
		if ( p == eof )
			goto _out128;
		p+= 1;
		st_case_128:
		if ( p == pe && p != eof )
			goto _out128;
		if ( p == eof ) {
			goto _st128;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st129;
			}
			goto _st0;
		}
		_st129:
		if ( p == eof )
			goto _out129;
		p+= 1;
		st_case_129:
		if ( p == pe && p != eof )
			goto _out129;
		if ( p == eof ) {
			goto _st129;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st130;
			}
			goto _st0;
		}
		_st130:
		if ( p == eof )
			goto _out130;
		p+= 1;
		st_case_130:
		if ( p == pe && p != eof )
			goto _out130;
		if ( p == eof ) {
			goto _st130;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st131;
			}
			goto _st0;
		}
		_st131:
		if ( p == eof )
			goto _out131;
		p+= 1;
		st_case_131:
		if ( p == pe && p != eof )
			goto _out131;
		if ( p == eof ) {
			goto _st131;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st132;
			}
			goto _st0;
		}
		_st132:
		if ( p == eof )
			goto _out132;
		p+= 1;
		st_case_132:
		if ( p == pe && p != eof )
			goto _out132;
		if ( p == eof ) {
			goto _st132;}
		else {
			if ( ( (*( p))) == 100 ) {
				goto _st133;
			}
			goto _st0;
		}
		_st133:
		if ( p == eof )
			goto _out133;
		p+= 1;
		st_case_133:
		if ( p == pe && p != eof )
			goto _out133;
		if ( p == eof ) {
			goto _st133;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st134;
			}
			goto _st0;
		}
		_st134:
		if ( p == eof )
			goto _out134;
		p+= 1;
		st_case_134:
		if ( p == pe && p != eof )
			goto _out134;
		if ( p == eof ) {
			goto _st134;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st135;
			}
			goto _st0;
		}
		_st135:
		if ( p == eof )
			goto _out135;
		p+= 1;
		st_case_135:
		if ( p == pe && p != eof )
			goto _out135;
		if ( p == eof ) {
			goto _st135;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st136;
			}
			goto _st0;
		}
		_st136:
		if ( p == eof )
			goto _out136;
		p+= 1;
		st_case_136:
		if ( p == pe && p != eof )
			goto _out136;
		if ( p == eof ) {
			goto _st136;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st137;
			}
			goto _st0;
		}
		_st137:
		if ( p == eof )
			goto _out137;
		p+= 1;
		st_case_137:
		if ( p == pe && p != eof )
			goto _out137;
		if ( p == eof ) {
			goto _st137;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st138;
			}
			goto _st0;
		}
		_st138:
		if ( p == eof )
			goto _out138;
		p+= 1;
		st_case_138:
		if ( p == pe && p != eof )
			goto _out138;
		if ( p == eof ) {
			goto _st138;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st139;
			}
			goto _st0;
		}
		_st139:
		if ( p == eof )
			goto _out139;
		p+= 1;
		st_case_139:
		if ( p == pe && p != eof )
			goto _out139;
		if ( p == eof ) {
			goto _st139;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr193;
			}
			goto _st0;
		}
		_st140:
		if ( p == eof )
			goto _out140;
		p+= 1;
		st_case_140:
		if ( p == pe && p != eof )
			goto _out140;
		if ( p == eof ) {
			goto _st140;}
		else {
			if ( ( (*( p))) == 117 ) {
				goto _st141;
			}
			goto _st0;
		}
		_st141:
		if ( p == eof )
			goto _out141;
		p+= 1;
		st_case_141:
		if ( p == pe && p != eof )
			goto _out141;
		if ( p == eof ) {
			goto _st141;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st142;
			}
			goto _st0;
		}
		_st142:
		if ( p == eof )
			goto _out142;
		p+= 1;
		st_case_142:
		if ( p == pe && p != eof )
			goto _out142;
		if ( p == eof ) {
			goto _st142;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st143;
			}
			goto _st0;
		}
		_st143:
		if ( p == eof )
			goto _out143;
		p+= 1;
		st_case_143:
		if ( p == pe && p != eof )
			goto _out143;
		if ( p == eof ) {
			goto _st143;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st144;
			}
			goto _st0;
		}
		_st144:
		if ( p == eof )
			goto _out144;
		p+= 1;
		st_case_144:
		if ( p == pe && p != eof )
			goto _out144;
		if ( p == eof ) {
			goto _st144;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st145;
			}
			goto _st0;
		}
		_st145:
		if ( p == eof )
			goto _out145;
		p+= 1;
		st_case_145:
		if ( p == pe && p != eof )
			goto _out145;
		if ( p == eof ) {
			goto _st145;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr198;
		}
		_ctr198:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 9737 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 9748 "cfg.c"
		
		goto _st146;
		_ctr200:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 9761 "cfg.c"
		
		goto _st146;
		_st146:
		if ( p == eof )
			goto _out146;
		p+= 1;
		st_case_146:
		if ( p == pe && p != eof )
			goto _out146;
		if ( p == eof ) {
			goto _st146;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr201;
			}
			goto _ctr200;
		}
		_st147:
		if ( p == eof )
			goto _out147;
		p+= 1;
		st_case_147:
		if ( p == pe && p != eof )
			goto _out147;
		if ( p == eof ) {
			goto _st147;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st148;
			}
			goto _st0;
		}
		_st148:
		if ( p == eof )
			goto _out148;
		p+= 1;
		st_case_148:
		if ( p == pe && p != eof )
			goto _out148;
		if ( p == eof ) {
			goto _st148;}
		else {
			if ( ( (*( p))) == 108 ) {
				goto _st149;
			}
			goto _st0;
		}
		_st149:
		if ( p == eof )
			goto _out149;
		p+= 1;
		st_case_149:
		if ( p == pe && p != eof )
			goto _out149;
		if ( p == eof ) {
			goto _st149;}
		else {
			if ( ( (*( p))) == 118 ) {
				goto _st150;
			}
			goto _st0;
		}
		_st150:
		if ( p == eof )
			goto _out150;
		p+= 1;
		st_case_150:
		if ( p == pe && p != eof )
			goto _out150;
		if ( p == eof ) {
			goto _st150;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st151;
			}
			goto _st0;
		}
		_st151:
		if ( p == eof )
			goto _out151;
		p+= 1;
		st_case_151:
		if ( p == pe && p != eof )
			goto _out151;
		if ( p == eof ) {
			goto _st151;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st152;
			}
			goto _st0;
		}
		_st152:
		if ( p == eof )
			goto _out152;
		p+= 1;
		st_case_152:
		if ( p == pe && p != eof )
			goto _out152;
		if ( p == eof ) {
			goto _st152;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st153;
			}
			goto _st0;
		}
		_st153:
		if ( p == eof )
			goto _out153;
		p+= 1;
		st_case_153:
		if ( p == pe && p != eof )
			goto _out153;
		if ( p == eof ) {
			goto _st153;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st154;
			}
			goto _st0;
		}
		_st154:
		if ( p == eof )
			goto _out154;
		p+= 1;
		st_case_154:
		if ( p == pe && p != eof )
			goto _out154;
		if ( p == eof ) {
			goto _st154;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st155;
			}
			goto _st0;
		}
		_st155:
		if ( p == eof )
			goto _out155;
		p+= 1;
		st_case_155:
		if ( p == pe && p != eof )
			goto _out155;
		if ( p == eof ) {
			goto _st155;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st156;
			}
			goto _st0;
		}
		_st156:
		if ( p == eof )
			goto _out156;
		p+= 1;
		st_case_156:
		if ( p == pe && p != eof )
			goto _out156;
		if ( p == eof ) {
			goto _st156;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr210;
		}
		_ctr210:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 9938 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 9949 "cfg.c"
		
		goto _st157;
		_ctr212:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 9962 "cfg.c"
		
		goto _st157;
		_st157:
		if ( p == eof )
			goto _out157;
		p+= 1;
		st_case_157:
		if ( p == pe && p != eof )
			goto _out157;
		if ( p == eof ) {
			goto _st157;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr213;
			}
			goto _ctr212;
		}
		_st158:
		if ( p == eof )
			goto _out158;
		p+= 1;
		st_case_158:
		if ( p == pe && p != eof )
			goto _out158;
		if ( p == eof ) {
			goto _st158;}
		else {
			if ( ( (*( p))) == 107 ) {
				goto _st159;
			}
			goto _st0;
		}
		_st159:
		if ( p == eof )
			goto _out159;
		p+= 1;
		st_case_159:
		if ( p == pe && p != eof )
			goto _out159;
		if ( p == eof ) {
			goto _st159;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st160;
			}
			goto _st0;
		}
		_st160:
		if ( p == eof )
			goto _out160;
		p+= 1;
		st_case_160:
		if ( p == pe && p != eof )
			goto _out160;
		if ( p == eof ) {
			goto _st160;}
		else {
			if ( ( (*( p))) == 108 ) {
				goto _st161;
			}
			goto _st0;
		}
		_st161:
		if ( p == eof )
			goto _out161;
		p+= 1;
		st_case_161:
		if ( p == pe && p != eof )
			goto _out161;
		if ( p == eof ) {
			goto _st161;}
		else {
			if ( ( (*( p))) == 108 ) {
				goto _st162;
			}
			goto _st0;
		}
		_st162:
		if ( p == eof )
			goto _out162;
		p+= 1;
		st_case_162:
		if ( p == pe && p != eof )
			goto _out162;
		if ( p == eof ) {
			goto _st162;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st163;
			}
			goto _st0;
		}
		_st163:
		if ( p == eof )
			goto _out163;
		p+= 1;
		st_case_163:
		if ( p == pe && p != eof )
			goto _out163;
		if ( p == eof ) {
			goto _st163;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st164;
			}
			goto _st0;
		}
		_st164:
		if ( p == eof )
			goto _out164;
		p+= 1;
		st_case_164:
		if ( p == pe && p != eof )
			goto _out164;
		if ( p == eof ) {
			goto _st164;}
		else {
			if ( ( (*( p))) == 100 ) {
				goto _st165;
			}
			goto _st0;
		}
		_st165:
		if ( p == eof )
			goto _out165;
		p+= 1;
		st_case_165:
		if ( p == pe && p != eof )
			goto _out165;
		if ( p == eof ) {
			goto _st165;}
		else {
			if ( ( (*( p))) == 120 ) {
				goto _st166;
			}
			goto _st0;
		}
		_st166:
		if ( p == eof )
			goto _out166;
		p+= 1;
		st_case_166:
		if ( p == pe && p != eof )
			goto _out166;
		if ( p == eof ) {
			goto _st166;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st167;
			}
			goto _st0;
		}
		_st167:
		if ( p == eof )
			goto _out167;
		p+= 1;
		st_case_167:
		if ( p == pe && p != eof )
			goto _out167;
		if ( p == eof ) {
			goto _st167;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr222;
		}
		_ctr222:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 10139 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 10150 "cfg.c"
		
		goto _st168;
		_ctr224:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 10163 "cfg.c"
		
		goto _st168;
		_st168:
		if ( p == eof )
			goto _out168;
		p+= 1;
		st_case_168:
		if ( p == pe && p != eof )
			goto _out168;
		if ( p == eof ) {
			goto _st168;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr225;
			}
			goto _ctr224;
		}
		_st169:
		if ( p == eof )
			goto _out169;
		p+= 1;
		st_case_169:
		if ( p == pe && p != eof )
			goto _out169;
		if ( p == eof ) {
			goto _st169;}
		else {
			switch( ( (*( p))) ) {
				case 54: {
					goto _st170;
				}
				case 99: {
					goto _st180;
				}
				case 101: {
					goto _st192;
				}
				case 111: {
					goto _st206;
				}
				case 116: {
					goto _st217;
				}
			}
			goto _st0;
		}
		_st170:
		if ( p == eof )
			goto _out170;
		p+= 1;
		st_case_170:
		if ( p == pe && p != eof )
			goto _out170;
		if ( p == eof ) {
			goto _st170;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st171;
			}
			goto _st0;
		}
		_st171:
		if ( p == eof )
			goto _out171;
		p+= 1;
		st_case_171:
		if ( p == pe && p != eof )
			goto _out171;
		if ( p == eof ) {
			goto _st171;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st172;
			}
			goto _st0;
		}
		_st172:
		if ( p == eof )
			goto _out172;
		p+= 1;
		st_case_172:
		if ( p == pe && p != eof )
			goto _out172;
		if ( p == eof ) {
			goto _st172;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st173;
			}
			goto _st0;
		}
		_st173:
		if ( p == eof )
			goto _out173;
		p+= 1;
		st_case_173:
		if ( p == pe && p != eof )
			goto _out173;
		if ( p == eof ) {
			goto _st173;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st174;
			}
			goto _st0;
		}
		_st174:
		if ( p == eof )
			goto _out174;
		p+= 1;
		st_case_174:
		if ( p == pe && p != eof )
			goto _out174;
		if ( p == eof ) {
			goto _st174;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st175;
			}
			goto _st0;
		}
		_st175:
		if ( p == eof )
			goto _out175;
		p+= 1;
		st_case_175:
		if ( p == pe && p != eof )
			goto _out175;
		if ( p == eof ) {
			goto _st175;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st176;
			}
			goto _st0;
		}
		_st176:
		if ( p == eof )
			goto _out176;
		p+= 1;
		st_case_176:
		if ( p == pe && p != eof )
			goto _out176;
		if ( p == eof ) {
			goto _st176;}
		else {
			if ( ( (*( p))) == 121 ) {
				goto _st177;
			}
			goto _st0;
		}
		_st177:
		if ( p == eof )
			goto _out177;
		p+= 1;
		st_case_177:
		if ( p == pe && p != eof )
			goto _out177;
		if ( p == eof ) {
			goto _st177;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st178;
			}
			goto _st0;
		}
		_st178:
		if ( p == eof )
			goto _out178;
		p+= 1;
		st_case_178:
		if ( p == pe && p != eof )
			goto _out178;
		if ( p == eof ) {
			goto _st178;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr238;
		}
		_ctr238:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 10354 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 10365 "cfg.c"
		
		goto _st179;
		_ctr240:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 10378 "cfg.c"
		
		goto _st179;
		_st179:
		if ( p == eof )
			goto _out179;
		p+= 1;
		st_case_179:
		if ( p == pe && p != eof )
			goto _out179;
		if ( p == eof ) {
			goto _st179;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr241;
			}
			goto _ctr240;
		}
		_st180:
		if ( p == eof )
			goto _out180;
		p+= 1;
		st_case_180:
		if ( p == pe && p != eof )
			goto _out180;
		if ( p == eof ) {
			goto _st180;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st181;
			}
			goto _st0;
		}
		_st181:
		if ( p == eof )
			goto _out181;
		p+= 1;
		st_case_181:
		if ( p == pe && p != eof )
			goto _out181;
		if ( p == eof ) {
			goto _st181;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st182;
			}
			goto _st0;
		}
		_st182:
		if ( p == eof )
			goto _out182;
		p+= 1;
		st_case_182:
		if ( p == pe && p != eof )
			goto _out182;
		if ( p == eof ) {
			goto _st182;}
		else {
			if ( ( (*( p))) == 112 ) {
				goto _st183;
			}
			goto _st0;
		}
		_st183:
		if ( p == eof )
			goto _out183;
		p+= 1;
		st_case_183:
		if ( p == pe && p != eof )
			goto _out183;
		if ( p == eof ) {
			goto _st183;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st184;
			}
			goto _st0;
		}
		_st184:
		if ( p == eof )
			goto _out184;
		p+= 1;
		st_case_184:
		if ( p == pe && p != eof )
			goto _out184;
		if ( p == eof ) {
			goto _st184;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st185;
			}
			goto _st0;
		}
		_st185:
		if ( p == eof )
			goto _out185;
		p+= 1;
		st_case_185:
		if ( p == pe && p != eof )
			goto _out185;
		if ( p == eof ) {
			goto _st185;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st186;
			}
			goto _st0;
		}
		_st186:
		if ( p == eof )
			goto _out186;
		p+= 1;
		st_case_186:
		if ( p == pe && p != eof )
			goto _out186;
		if ( p == eof ) {
			goto _st186;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st187;
			}
			goto _st0;
		}
		_st187:
		if ( p == eof )
			goto _out187;
		p+= 1;
		st_case_187:
		if ( p == pe && p != eof )
			goto _out187;
		if ( p == eof ) {
			goto _st187;}
		else {
			if ( ( (*( p))) == 108 ) {
				goto _st188;
			}
			goto _st0;
		}
		_st188:
		if ( p == eof )
			goto _out188;
		p+= 1;
		st_case_188:
		if ( p == pe && p != eof )
			goto _out188;
		if ( p == eof ) {
			goto _st188;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st189;
			}
			goto _st0;
		}
		_st189:
		if ( p == eof )
			goto _out189;
		p+= 1;
		st_case_189:
		if ( p == pe && p != eof )
			goto _out189;
		if ( p == eof ) {
			goto _st189;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st190;
			}
			goto _st0;
		}
		_st190:
		if ( p == eof )
			goto _out190;
		p+= 1;
		st_case_190:
		if ( p == pe && p != eof )
			goto _out190;
		if ( p == eof ) {
			goto _st190;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr251;
		}
		_ctr251:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 10570 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 10581 "cfg.c"
		
		goto _st191;
		_ctr253:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 10594 "cfg.c"
		
		goto _st191;
		_st191:
		if ( p == eof )
			goto _out191;
		p+= 1;
		st_case_191:
		if ( p == pe && p != eof )
			goto _out191;
		if ( p == eof ) {
			goto _st191;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr254;
			}
			goto _ctr253;
		}
		_st192:
		if ( p == eof )
			goto _out192;
		p+= 1;
		st_case_192:
		if ( p == pe && p != eof )
			goto _out192;
		if ( p == eof ) {
			goto _st192;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st193;
			}
			goto _st0;
		}
		_st193:
		if ( p == eof )
			goto _out193;
		p+= 1;
		st_case_193:
		if ( p == pe && p != eof )
			goto _out193;
		if ( p == eof ) {
			goto _st193;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st194;
			}
			goto _st0;
		}
		_st194:
		if ( p == eof )
			goto _out194;
		p+= 1;
		st_case_194:
		if ( p == pe && p != eof )
			goto _out194;
		if ( p == eof ) {
			goto _st194;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st195;
			}
			goto _st0;
		}
		_st195:
		if ( p == eof )
			goto _out195;
		p+= 1;
		st_case_195:
		if ( p == pe && p != eof )
			goto _out195;
		if ( p == eof ) {
			goto _st195;}
		else {
			if ( ( (*( p))) == 109 ) {
				goto _st196;
			}
			goto _st0;
		}
		_st196:
		if ( p == eof )
			goto _out196;
		p+= 1;
		st_case_196:
		if ( p == pe && p != eof )
			goto _out196;
		if ( p == eof ) {
			goto _st196;}
		else {
			if ( ( (*( p))) == 112 ) {
				goto _st197;
			}
			goto _st0;
		}
		_st197:
		if ( p == eof )
			goto _out197;
		p+= 1;
		st_case_197:
		if ( p == pe && p != eof )
			goto _out197;
		if ( p == eof ) {
			goto _st197;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st198;
			}
			goto _st0;
		}
		_st198:
		if ( p == eof )
			goto _out198;
		p+= 1;
		st_case_198:
		if ( p == pe && p != eof )
			goto _out198;
		if ( p == eof ) {
			goto _st198;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st199;
			}
			goto _st0;
		}
		_st199:
		if ( p == eof )
			goto _out199;
		p+= 1;
		st_case_199:
		if ( p == pe && p != eof )
			goto _out199;
		if ( p == eof ) {
			goto _st199;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st200;
			}
			goto _st0;
		}
		_st200:
		if ( p == eof )
			goto _out200;
		p+= 1;
		st_case_200:
		if ( p == pe && p != eof )
			goto _out200;
		if ( p == eof ) {
			goto _st200;}
		else {
			if ( ( (*( p))) == 102 ) {
				goto _st201;
			}
			goto _st0;
		}
		_st201:
		if ( p == eof )
			goto _out201;
		p+= 1;
		st_case_201:
		if ( p == pe && p != eof )
			goto _out201;
		if ( p == eof ) {
			goto _st201;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st202;
			}
			goto _st0;
		}
		_st202:
		if ( p == eof )
			goto _out202;
		p+= 1;
		st_case_202:
		if ( p == pe && p != eof )
			goto _out202;
		if ( p == eof ) {
			goto _st202;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st203;
			}
			goto _st0;
		}
		_st203:
		if ( p == eof )
			goto _out203;
		p+= 1;
		st_case_203:
		if ( p == pe && p != eof )
			goto _out203;
		if ( p == eof ) {
			goto _st203;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st204;
			}
			goto _st0;
		}
		_st204:
		if ( p == eof )
			goto _out204;
		p+= 1;
		st_case_204:
		if ( p == pe && p != eof )
			goto _out204;
		if ( p == eof ) {
			goto _st204;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st205;
			}
			goto _st0;
		}
		_st205:
		if ( p == eof )
			goto _out205;
		p+= 1;
		st_case_205:
		if ( p == pe && p != eof )
			goto _out205;
		if ( p == eof ) {
			goto _st205;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr267;
			}
			goto _st0;
		}
		_st206:
		if ( p == eof )
			goto _out206;
		p+= 1;
		st_case_206:
		if ( p == pe && p != eof )
			goto _out206;
		if ( p == eof ) {
			goto _st206;}
		else {
			if ( ( (*( p))) == 99 ) {
				goto _st207;
			}
			goto _st0;
		}
		_st207:
		if ( p == eof )
			goto _out207;
		p+= 1;
		st_case_207:
		if ( p == pe && p != eof )
			goto _out207;
		if ( p == eof ) {
			goto _st207;}
		else {
			if ( ( (*( p))) == 107 ) {
				goto _st208;
			}
			goto _st0;
		}
		_st208:
		if ( p == eof )
			goto _out208;
		p+= 1;
		st_case_208:
		if ( p == pe && p != eof )
			goto _out208;
		if ( p == eof ) {
			goto _st208;}
		else {
			if ( ( (*( p))) == 100 ) {
				goto _st209;
			}
			goto _st0;
		}
		_st209:
		if ( p == eof )
			goto _out209;
		p+= 1;
		st_case_209:
		if ( p == pe && p != eof )
			goto _out209;
		if ( p == eof ) {
			goto _st209;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st210;
			}
			goto _st0;
		}
		_st210:
		if ( p == eof )
			goto _out210;
		p+= 1;
		st_case_210:
		if ( p == pe && p != eof )
			goto _out210;
		if ( p == eof ) {
			goto _st210;}
		else {
			if ( ( (*( p))) == 117 ) {
				goto _st211;
			}
			goto _st0;
		}
		_st211:
		if ( p == eof )
			goto _out211;
		p+= 1;
		st_case_211:
		if ( p == pe && p != eof )
			goto _out211;
		if ( p == eof ) {
			goto _st211;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st212;
			}
			goto _st0;
		}
		_st212:
		if ( p == eof )
			goto _out212;
		p+= 1;
		st_case_212:
		if ( p == pe && p != eof )
			goto _out212;
		if ( p == eof ) {
			goto _st212;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st213;
			}
			goto _st0;
		}
		_st213:
		if ( p == eof )
			goto _out213;
		p+= 1;
		st_case_213:
		if ( p == pe && p != eof )
			goto _out213;
		if ( p == eof ) {
			goto _st213;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st214;
			}
			goto _st0;
		}
		_st214:
		if ( p == eof )
			goto _out214;
		p+= 1;
		st_case_214:
		if ( p == pe && p != eof )
			goto _out214;
		if ( p == eof ) {
			goto _st214;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st215;
			}
			goto _st0;
		}
		_st215:
		if ( p == eof )
			goto _out215;
		p+= 1;
		st_case_215:
		if ( p == pe && p != eof )
			goto _out215;
		if ( p == eof ) {
			goto _st215;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr276;
		}
		_ctr276:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 10981 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 10992 "cfg.c"
		
		goto _st216;
		_ctr278:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 11005 "cfg.c"
		
		goto _st216;
		_st216:
		if ( p == eof )
			goto _out216;
		p+= 1;
		st_case_216:
		if ( p == pe && p != eof )
			goto _out216;
		if ( p == eof ) {
			goto _st216;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr279;
			}
			goto _ctr278;
		}
		_st217:
		if ( p == eof )
			goto _out217;
		p+= 1;
		st_case_217:
		if ( p == pe && p != eof )
			goto _out217;
		if ( p == eof ) {
			goto _st217;}
		else {
			if ( ( (*( p))) == 97 ) {
				goto _st218;
			}
			goto _st0;
		}
		_st218:
		if ( p == eof )
			goto _out218;
		p+= 1;
		st_case_218:
		if ( p == pe && p != eof )
			goto _out218;
		if ( p == eof ) {
			goto _st218;}
		else {
			if ( ( (*( p))) == 116 ) {
				goto _st219;
			}
			goto _st0;
		}
		_st219:
		if ( p == eof )
			goto _out219;
		p+= 1;
		st_case_219:
		if ( p == pe && p != eof )
			goto _out219;
		if ( p == eof ) {
			goto _st219;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st220;
			}
			goto _st0;
		}
		_st220:
		if ( p == eof )
			goto _out220;
		p+= 1;
		st_case_220:
		if ( p == pe && p != eof )
			goto _out220;
		if ( p == eof ) {
			goto _st220;}
		else {
			if ( ( (*( p))) == 45 ) {
				goto _st221;
			}
			goto _st0;
		}
		_st221:
		if ( p == eof )
			goto _out221;
		p+= 1;
		st_case_221:
		if ( p == pe && p != eof )
			goto _out221;
		if ( p == eof ) {
			goto _st221;}
		else {
			if ( ( (*( p))) == 100 ) {
				goto _st222;
			}
			goto _st0;
		}
		_st222:
		if ( p == eof )
			goto _out222;
		p+= 1;
		st_case_222:
		if ( p == pe && p != eof )
			goto _out222;
		if ( p == eof ) {
			goto _st222;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st223;
			}
			goto _st0;
		}
		_st223:
		if ( p == eof )
			goto _out223;
		p+= 1;
		st_case_223:
		if ( p == pe && p != eof )
			goto _out223;
		if ( p == eof ) {
			goto _st223;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st224;
			}
			goto _st0;
		}
		_st224:
		if ( p == eof )
			goto _out224;
		p+= 1;
		st_case_224:
		if ( p == pe && p != eof )
			goto _out224;
		if ( p == eof ) {
			goto _st224;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st225;
			}
			goto _st0;
		}
		_st225:
		if ( p == eof )
			goto _out225;
		p+= 1;
		st_case_225:
		if ( p == pe && p != eof )
			goto _out225;
		if ( p == eof ) {
			goto _st225;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr287;
		}
		_ctr287:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 11167 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 11178 "cfg.c"
		
		goto _st226;
		_ctr289:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 11191 "cfg.c"
		
		goto _st226;
		_st226:
		if ( p == eof )
			goto _out226;
		p+= 1;
		st_case_226:
		if ( p == pe && p != eof )
			goto _out226;
		if ( p == eof ) {
			goto _st226;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr290;
			}
			goto _ctr289;
		}
		_st227:
		if ( p == eof )
			goto _out227;
		p+= 1;
		st_case_227:
		if ( p == pe && p != eof )
			goto _out227;
		if ( p == eof ) {
			goto _st227;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st228;
			}
			goto _st0;
		}
		_st228:
		if ( p == eof )
			goto _out228;
		p+= 1;
		st_case_228:
		if ( p == pe && p != eof )
			goto _out228;
		if ( p == eof ) {
			goto _st228;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st229;
			}
			goto _st0;
		}
		_st229:
		if ( p == eof )
			goto _out229;
		p+= 1;
		st_case_229:
		if ( p == pe && p != eof )
			goto _out229;
		if ( p == eof ) {
			goto _st229;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st230;
			}
			goto _st0;
		}
		_st230:
		if ( p == eof )
			goto _out230;
		p+= 1;
		st_case_230:
		if ( p == pe && p != eof )
			goto _out230;
		if ( p == eof ) {
			goto _st230;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st231;
			}
			goto _st0;
		}
		_st231:
		if ( p == eof )
			goto _out231;
		p+= 1;
		st_case_231:
		if ( p == pe && p != eof )
			goto _out231;
		if ( p == eof ) {
			goto _st231;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr294;
		}
		_ctr294:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 11293 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 11304 "cfg.c"
		
		goto _st232;
		_ctr296:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 11317 "cfg.c"
		
		goto _st232;
		_st232:
		if ( p == eof )
			goto _out232;
		p+= 1;
		st_case_232:
		if ( p == pe && p != eof )
			goto _out232;
		if ( p == eof ) {
			goto _st232;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr297;
			}
			goto _ctr296;
		}
		_st233:
		if ( p == eof )
			goto _out233;
		p+= 1;
		st_case_233:
		if ( p == pe && p != eof )
			goto _out233;
		if ( p == eof ) {
			goto _st233;}
		else {
			if ( ( (*( p))) == 101 ) {
				goto _st234;
			}
			goto _st0;
		}
		_st234:
		if ( p == eof )
			goto _out234;
		p+= 1;
		st_case_234:
		if ( p == pe && p != eof )
			goto _out234;
		if ( p == eof ) {
			goto _st234;}
		else {
			switch( ( (*( p))) ) {
				case 110: {
					goto _st235;
				}
				case 114: {
					goto _st243;
				}
			}
			goto _st0;
		}
		_st235:
		if ( p == eof )
			goto _out235;
		p+= 1;
		st_case_235:
		if ( p == pe && p != eof )
			goto _out235;
		if ( p == eof ) {
			goto _st235;}
		else {
			if ( ( (*( p))) == 100 ) {
				goto _st236;
			}
			goto _st0;
		}
		_st236:
		if ( p == eof )
			goto _out236;
		p+= 1;
		st_case_236:
		if ( p == pe && p != eof )
			goto _out236;
		if ( p == eof ) {
			goto _st236;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st237;
			}
			goto _st0;
		}
		_st237:
		if ( p == eof )
			goto _out237;
		p+= 1;
		st_case_237:
		if ( p == pe && p != eof )
			goto _out237;
		if ( p == eof ) {
			goto _st237;}
		else {
			if ( ( (*( p))) == 114 ) {
				goto _st238;
			}
			goto _st0;
		}
		_st238:
		if ( p == eof )
			goto _out238;
		p+= 1;
		st_case_238:
		if ( p == pe && p != eof )
			goto _out238;
		if ( p == eof ) {
			goto _st238;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st239;
			}
			goto _st0;
		}
		_st239:
		if ( p == eof )
			goto _out239;
		p+= 1;
		st_case_239:
		if ( p == pe && p != eof )
			goto _out239;
		if ( p == eof ) {
			goto _st239;}
		else {
			if ( ( (*( p))) == 100 ) {
				goto _st240;
			}
			goto _st0;
		}
		_st240:
		if ( p == eof )
			goto _out240;
		p+= 1;
		st_case_240:
		if ( p == pe && p != eof )
			goto _out240;
		if ( p == eof ) {
			goto _st240;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st241;
			}
			goto _st0;
		}
		_st241:
		if ( p == eof )
			goto _out241;
		p+= 1;
		st_case_241:
		if ( p == pe && p != eof )
			goto _out241;
		if ( p == eof ) {
			goto _st241;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _st0;
			}
			goto _ctr306;
		}
		_ctr306:
		{
#line 39 "cfg.rl"
			
			memset(&ccfg.buf, 0, sizeof ccfg.buf);
			ccfg.buflen = 0;
			ccfg.ternary = 0;
		}
		
#line 11484 "cfg.c"
		
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 11495 "cfg.c"
		
		goto _st242;
		_ctr308:
		{
#line 44 "cfg.rl"
			
			if (ccfg.buflen < sizeof ccfg.buf - 1)
			ccfg.buf[ccfg.buflen++] = *p;
			else
			suicide("line or option is too long");
		}
		
#line 11508 "cfg.c"
		
		goto _st242;
		_st242:
		if ( p == eof )
			goto _out242;
		p+= 1;
		st_case_242:
		if ( p == pe && p != eof )
			goto _out242;
		if ( p == eof ) {
			goto _st242;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr309;
			}
			goto _ctr308;
		}
		_st243:
		if ( p == eof )
			goto _out243;
		p+= 1;
		st_case_243:
		if ( p == pe && p != eof )
			goto _out243;
		if ( p == eof ) {
			goto _st243;}
		else {
			if ( ( (*( p))) == 115 ) {
				goto _st244;
			}
			goto _st0;
		}
		_st244:
		if ( p == eof )
			goto _out244;
		p+= 1;
		st_case_244:
		if ( p == pe && p != eof )
			goto _out244;
		if ( p == eof ) {
			goto _st244;}
		else {
			if ( ( (*( p))) == 105 ) {
				goto _st245;
			}
			goto _st0;
		}
		_st245:
		if ( p == eof )
			goto _out245;
		p+= 1;
		st_case_245:
		if ( p == pe && p != eof )
			goto _out245;
		if ( p == eof ) {
			goto _st245;}
		else {
			if ( ( (*( p))) == 111 ) {
				goto _st246;
			}
			goto _st0;
		}
		_st246:
		if ( p == eof )
			goto _out246;
		p+= 1;
		st_case_246:
		if ( p == pe && p != eof )
			goto _out246;
		if ( p == eof ) {
			goto _st246;}
		else {
			if ( ( (*( p))) == 110 ) {
				goto _st247;
			}
			goto _st0;
		}
		_st247:
		if ( p == eof )
			goto _out247;
		p+= 1;
		st_case_247:
		if ( p == pe && p != eof )
			goto _out247;
		if ( p == eof ) {
			goto _st247;}
		else {
			if ( ( (*( p))) == 0 ) {
				goto _ctr313;
			}
			goto _st0;
		}
		_out248: ccfg.cs = 248; goto _out; 
		_out0: ccfg.cs = 0; goto _out; 
		_out1: ccfg.cs = 1; goto _out; 
		_out2: ccfg.cs = 2; goto _out; 
		_out3: ccfg.cs = 3; goto _out; 
		_out4: ccfg.cs = 4; goto _out; 
		_out5: ccfg.cs = 5; goto _out; 
		_out6: ccfg.cs = 6; goto _out; 
		_out7: ccfg.cs = 7; goto _out; 
		_out8: ccfg.cs = 8; goto _out; 
		_out9: ccfg.cs = 9; goto _out; 
		_out10: ccfg.cs = 10; goto _out; 
		_out11: ccfg.cs = 11; goto _out; 
		_out12: ccfg.cs = 12; goto _out; 
		_out13: ccfg.cs = 13; goto _out; 
		_out14: ccfg.cs = 14; goto _out; 
		_out15: ccfg.cs = 15; goto _out; 
		_out16: ccfg.cs = 16; goto _out; 
		_out17: ccfg.cs = 17; goto _out; 
		_out18: ccfg.cs = 18; goto _out; 
		_out19: ccfg.cs = 19; goto _out; 
		_out20: ccfg.cs = 20; goto _out; 
		_out21: ccfg.cs = 21; goto _out; 
		_out22: ccfg.cs = 22; goto _out; 
		_out23: ccfg.cs = 23; goto _out; 
		_out24: ccfg.cs = 24; goto _out; 
		_out25: ccfg.cs = 25; goto _out; 
		_out26: ccfg.cs = 26; goto _out; 
		_out27: ccfg.cs = 27; goto _out; 
		_out28: ccfg.cs = 28; goto _out; 
		_out29: ccfg.cs = 29; goto _out; 
		_out30: ccfg.cs = 30; goto _out; 
		_out31: ccfg.cs = 31; goto _out; 
		_out32: ccfg.cs = 32; goto _out; 
		_out33: ccfg.cs = 33; goto _out; 
		_out34: ccfg.cs = 34; goto _out; 
		_out35: ccfg.cs = 35; goto _out; 
		_out36: ccfg.cs = 36; goto _out; 
		_out37: ccfg.cs = 37; goto _out; 
		_out38: ccfg.cs = 38; goto _out; 
		_out39: ccfg.cs = 39; goto _out; 
		_out40: ccfg.cs = 40; goto _out; 
		_out41: ccfg.cs = 41; goto _out; 
		_out42: ccfg.cs = 42; goto _out; 
		_out43: ccfg.cs = 43; goto _out; 
		_out44: ccfg.cs = 44; goto _out; 
		_out45: ccfg.cs = 45; goto _out; 
		_out46: ccfg.cs = 46; goto _out; 
		_out47: ccfg.cs = 47; goto _out; 
		_out48: ccfg.cs = 48; goto _out; 
		_out49: ccfg.cs = 49; goto _out; 
		_out50: ccfg.cs = 50; goto _out; 
		_out51: ccfg.cs = 51; goto _out; 
		_out52: ccfg.cs = 52; goto _out; 
		_out53: ccfg.cs = 53; goto _out; 
		_out54: ccfg.cs = 54; goto _out; 
		_out55: ccfg.cs = 55; goto _out; 
		_out56: ccfg.cs = 56; goto _out; 
		_out57: ccfg.cs = 57; goto _out; 
		_out58: ccfg.cs = 58; goto _out; 
		_out59: ccfg.cs = 59; goto _out; 
		_out60: ccfg.cs = 60; goto _out; 
		_out61: ccfg.cs = 61; goto _out; 
		_out62: ccfg.cs = 62; goto _out; 
		_out63: ccfg.cs = 63; goto _out; 
		_out64: ccfg.cs = 64; goto _out; 
		_out65: ccfg.cs = 65; goto _out; 
		_out66: ccfg.cs = 66; goto _out; 
		_out67: ccfg.cs = 67; goto _out; 
		_out68: ccfg.cs = 68; goto _out; 
		_out69: ccfg.cs = 69; goto _out; 
		_out70: ccfg.cs = 70; goto _out; 
		_out71: ccfg.cs = 71; goto _out; 
		_out72: ccfg.cs = 72; goto _out; 
		_out73: ccfg.cs = 73; goto _out; 
		_out249: ccfg.cs = 249; goto _out; 
		_out74: ccfg.cs = 74; goto _out; 
		_out75: ccfg.cs = 75; goto _out; 
		_out76: ccfg.cs = 76; goto _out; 
		_out77: ccfg.cs = 77; goto _out; 
		_out78: ccfg.cs = 78; goto _out; 
		_out79: ccfg.cs = 79; goto _out; 
		_out80: ccfg.cs = 80; goto _out; 
		_out81: ccfg.cs = 81; goto _out; 
		_out82: ccfg.cs = 82; goto _out; 
		_out83: ccfg.cs = 83; goto _out; 
		_out84: ccfg.cs = 84; goto _out; 
		_out85: ccfg.cs = 85; goto _out; 
		_out86: ccfg.cs = 86; goto _out; 
		_out87: ccfg.cs = 87; goto _out; 
		_out88: ccfg.cs = 88; goto _out; 
		_out89: ccfg.cs = 89; goto _out; 
		_out90: ccfg.cs = 90; goto _out; 
		_out91: ccfg.cs = 91; goto _out; 
		_out92: ccfg.cs = 92; goto _out; 
		_out93: ccfg.cs = 93; goto _out; 
		_out94: ccfg.cs = 94; goto _out; 
		_out95: ccfg.cs = 95; goto _out; 
		_out96: ccfg.cs = 96; goto _out; 
		_out97: ccfg.cs = 97; goto _out; 
		_out98: ccfg.cs = 98; goto _out; 
		_out99: ccfg.cs = 99; goto _out; 
		_out100: ccfg.cs = 100; goto _out; 
		_out101: ccfg.cs = 101; goto _out; 
		_out102: ccfg.cs = 102; goto _out; 
		_out103: ccfg.cs = 103; goto _out; 
		_out104: ccfg.cs = 104; goto _out; 
		_out105: ccfg.cs = 105; goto _out; 
		_out106: ccfg.cs = 106; goto _out; 
		_out107: ccfg.cs = 107; goto _out; 
		_out108: ccfg.cs = 108; goto _out; 
		_out109: ccfg.cs = 109; goto _out; 
		_out110: ccfg.cs = 110; goto _out; 
		_out111: ccfg.cs = 111; goto _out; 
		_out112: ccfg.cs = 112; goto _out; 
		_out113: ccfg.cs = 113; goto _out; 
		_out114: ccfg.cs = 114; goto _out; 
		_out115: ccfg.cs = 115; goto _out; 
		_out116: ccfg.cs = 116; goto _out; 
		_out117: ccfg.cs = 117; goto _out; 
		_out118: ccfg.cs = 118; goto _out; 
		_out119: ccfg.cs = 119; goto _out; 
		_out120: ccfg.cs = 120; goto _out; 
		_out121: ccfg.cs = 121; goto _out; 
		_out122: ccfg.cs = 122; goto _out; 
		_out123: ccfg.cs = 123; goto _out; 
		_out124: ccfg.cs = 124; goto _out; 
		_out125: ccfg.cs = 125; goto _out; 
		_out126: ccfg.cs = 126; goto _out; 
		_out127: ccfg.cs = 127; goto _out; 
		_out128: ccfg.cs = 128; goto _out; 
		_out129: ccfg.cs = 129; goto _out; 
		_out130: ccfg.cs = 130; goto _out; 
		_out131: ccfg.cs = 131; goto _out; 
		_out132: ccfg.cs = 132; goto _out; 
		_out133: ccfg.cs = 133; goto _out; 
		_out134: ccfg.cs = 134; goto _out; 
		_out135: ccfg.cs = 135; goto _out; 
		_out136: ccfg.cs = 136; goto _out; 
		_out137: ccfg.cs = 137; goto _out; 
		_out138: ccfg.cs = 138; goto _out; 
		_out139: ccfg.cs = 139; goto _out; 
		_out140: ccfg.cs = 140; goto _out; 
		_out141: ccfg.cs = 141; goto _out; 
		_out142: ccfg.cs = 142; goto _out; 
		_out143: ccfg.cs = 143; goto _out; 
		_out144: ccfg.cs = 144; goto _out; 
		_out145: ccfg.cs = 145; goto _out; 
		_out146: ccfg.cs = 146; goto _out; 
		_out147: ccfg.cs = 147; goto _out; 
		_out148: ccfg.cs = 148; goto _out; 
		_out149: ccfg.cs = 149; goto _out; 
		_out150: ccfg.cs = 150; goto _out; 
		_out151: ccfg.cs = 151; goto _out; 
		_out152: ccfg.cs = 152; goto _out; 
		_out153: ccfg.cs = 153; goto _out; 
		_out154: ccfg.cs = 154; goto _out; 
		_out155: ccfg.cs = 155; goto _out; 
		_out156: ccfg.cs = 156; goto _out; 
		_out157: ccfg.cs = 157; goto _out; 
		_out158: ccfg.cs = 158; goto _out; 
		_out159: ccfg.cs = 159; goto _out; 
		_out160: ccfg.cs = 160; goto _out; 
		_out161: ccfg.cs = 161; goto _out; 
		_out162: ccfg.cs = 162; goto _out; 
		_out163: ccfg.cs = 163; goto _out; 
		_out164: ccfg.cs = 164; goto _out; 
		_out165: ccfg.cs = 165; goto _out; 
		_out166: ccfg.cs = 166; goto _out; 
		_out167: ccfg.cs = 167; goto _out; 
		_out168: ccfg.cs = 168; goto _out; 
		_out169: ccfg.cs = 169; goto _out; 
		_out170: ccfg.cs = 170; goto _out; 
		_out171: ccfg.cs = 171; goto _out; 
		_out172: ccfg.cs = 172; goto _out; 
		_out173: ccfg.cs = 173; goto _out; 
		_out174: ccfg.cs = 174; goto _out; 
		_out175: ccfg.cs = 175; goto _out; 
		_out176: ccfg.cs = 176; goto _out; 
		_out177: ccfg.cs = 177; goto _out; 
		_out178: ccfg.cs = 178; goto _out; 
		_out179: ccfg.cs = 179; goto _out; 
		_out180: ccfg.cs = 180; goto _out; 
		_out181: ccfg.cs = 181; goto _out; 
		_out182: ccfg.cs = 182; goto _out; 
		_out183: ccfg.cs = 183; goto _out; 
		_out184: ccfg.cs = 184; goto _out; 
		_out185: ccfg.cs = 185; goto _out; 
		_out186: ccfg.cs = 186; goto _out; 
		_out187: ccfg.cs = 187; goto _out; 
		_out188: ccfg.cs = 188; goto _out; 
		_out189: ccfg.cs = 189; goto _out; 
		_out190: ccfg.cs = 190; goto _out; 
		_out191: ccfg.cs = 191; goto _out; 
		_out192: ccfg.cs = 192; goto _out; 
		_out193: ccfg.cs = 193; goto _out; 
		_out194: ccfg.cs = 194; goto _out; 
		_out195: ccfg.cs = 195; goto _out; 
		_out196: ccfg.cs = 196; goto _out; 
		_out197: ccfg.cs = 197; goto _out; 
		_out198: ccfg.cs = 198; goto _out; 
		_out199: ccfg.cs = 199; goto _out; 
		_out200: ccfg.cs = 200; goto _out; 
		_out201: ccfg.cs = 201; goto _out; 
		_out202: ccfg.cs = 202; goto _out; 
		_out203: ccfg.cs = 203; goto _out; 
		_out204: ccfg.cs = 204; goto _out; 
		_out205: ccfg.cs = 205; goto _out; 
		_out206: ccfg.cs = 206; goto _out; 
		_out207: ccfg.cs = 207; goto _out; 
		_out208: ccfg.cs = 208; goto _out; 
		_out209: ccfg.cs = 209; goto _out; 
		_out210: ccfg.cs = 210; goto _out; 
		_out211: ccfg.cs = 211; goto _out; 
		_out212: ccfg.cs = 212; goto _out; 
		_out213: ccfg.cs = 213; goto _out; 
		_out214: ccfg.cs = 214; goto _out; 
		_out215: ccfg.cs = 215; goto _out; 
		_out216: ccfg.cs = 216; goto _out; 
		_out217: ccfg.cs = 217; goto _out; 
		_out218: ccfg.cs = 218; goto _out; 
		_out219: ccfg.cs = 219; goto _out; 
		_out220: ccfg.cs = 220; goto _out; 
		_out221: ccfg.cs = 221; goto _out; 
		_out222: ccfg.cs = 222; goto _out; 
		_out223: ccfg.cs = 223; goto _out; 
		_out224: ccfg.cs = 224; goto _out; 
		_out225: ccfg.cs = 225; goto _out; 
		_out226: ccfg.cs = 226; goto _out; 
		_out227: ccfg.cs = 227; goto _out; 
		_out228: ccfg.cs = 228; goto _out; 
		_out229: ccfg.cs = 229; goto _out; 
		_out230: ccfg.cs = 230; goto _out; 
		_out231: ccfg.cs = 231; goto _out; 
		_out232: ccfg.cs = 232; goto _out; 
		_out233: ccfg.cs = 233; goto _out; 
		_out234: ccfg.cs = 234; goto _out; 
		_out235: ccfg.cs = 235; goto _out; 
		_out236: ccfg.cs = 236; goto _out; 
		_out237: ccfg.cs = 237; goto _out; 
		_out238: ccfg.cs = 238; goto _out; 
		_out239: ccfg.cs = 239; goto _out; 
		_out240: ccfg.cs = 240; goto _out; 
		_out241: ccfg.cs = 241; goto _out; 
		_out242: ccfg.cs = 242; goto _out; 
		_out243: ccfg.cs = 243; goto _out; 
		_out244: ccfg.cs = 244; goto _out; 
		_out245: ccfg.cs = 245; goto _out; 
		_out246: ccfg.cs = 246; goto _out; 
		_out247: ccfg.cs = 247; goto _out; 
		_out: {}
	}
	
#line 351 "cfg.rl"
	
	
	if (ccfg.cs == cmd_cfg_error)
		suicide("error parsing command line option: malformed");
	if (ccfg.cs >= cmd_cfg_first_final)
		return;
	suicide("error parsing command line option: incomplete");
}

