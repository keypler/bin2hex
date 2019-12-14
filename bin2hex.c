/* bin2hex Intel-Hex converter
   Copyright (c) 2006 Hans Rosenfeld

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.

*/

#include "bin2hex.h"
#include "endian.h"
#include "intel.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <inttypes.h>

extern char *optarg;
extern int optind;
extern int optopt;
extern int opterr;

uint32_t quiet   = 0;
uint32_t zero    = 0;
uint32_t entry   = 0;
uint32_t eflag   = 0;
uint32_t segment = 0;
uint32_t segflag = 0;
uint32_t linflag = 0;
uint32_t twiddle = 0;

struct binfmt binfmt[] = {
        BINFMT(aout16, "16bit a.out (PDP-11 Unix executable)"),
        BINFMT(aout32, "32bit a.out (Unix executable)"), 
        BINFMT(elf, "ELF (Executable & Linking Format)"),
        BINFMT(exe, "EXE (DOS executable)"),
        BINFMT(bin, "flat binary"),
        BINFMT(com, "flat binary (DOS .COM executable)"),
        BINFMT(sav, "flat binary (RT-11 .SAV executable)"),
        BINFMT(rel, "flat binary (RT-11 .REL executable)"),
        { 0, 0, 0, 0 }
};

void usage(void)
{
        fprintf(stderr, "usage: bin2hex [flags] input-file\n\n");
        fprintf(stderr, "\t-f\t\tlist known input formats and exit\n");
        fprintf(stderr, "\t-q\t\tquiet operation\n");
        fprintf(stderr, "\t-t\t\ttwiddle endianness\n");
        fprintf(stderr, "\t-s\t\tuse segment address records\n");
        fprintf(stderr, "\t-l\t\tuse linear address records\n");
        fprintf(stderr, "\t-z\t\tsuppress data records with all bytes zero\n");
        fprintf(stderr, "\t-b base\t\tstart output at specified address (output address 0)\n");
        fprintf(stderr, "\t-r reloc\trelocate output to specified address\n");
        fprintf(stderr, "\t-c seg\t\tset/override extended segment address record\n");
        fprintf(stderr, "\t-e entry\tset entry point (segment:offset or linar address)\n");
        fprintf(stderr, "\t-i format\tforce input format\n");
        fprintf(stderr, "\t-o file\t\toutput filename\n");
        fprintf(stderr, "\nIf no output file is specified, standard output will be used.\n");
        exit(1);
}

int main(int argc, char **argv)
{
        uint32_t addr=0, base=0;
        uint8_t *buf=NULL;
	char *ext=NULL, *fmt=NULL;
	int ch;
        FILE *in=stdin, *out=stdout;
        struct binfmt *bptr;

        get_endian();

        while((ch = getopt(argc, argv, "tslzhfqb:r:o:i:e:c:")) != -1) {
                switch(ch) {
                case 't':
                        twiddle = 1;
                        break;
                case 's':
                        segflag = 1;
                        break;
                case 'l':
                        linflag = 1;
                        break;
                case 'z':
                        zero = 1;
                        break;
                case 'q':
                        quiet = 1;
                        break;
                case 'i':
                        fmt = optarg;
                        break;
                case 'f':
                        fprintf(stderr, "known input formats:\n\n");
                        for(bptr = binfmt; bptr->name; bptr++)
                                fprintf(stderr, "\t%s\t%s\n", bptr->name, bptr->descr);
                        exit(0);
                        break;
                case 'b':
                        if(!sscanf(optarg, "%" SCNu32, &base)) {
                                fprintf(stderr, "base address parse error\n");
                                exit(1);
                        }
                        break;
                case 'r':
                        if(!sscanf(optarg, "%" SCNu32, &addr)) {
                                fprintf(stderr, "relocation address parse error\n");
                                exit(1);
                        }
                        break;
                case 'o':
                        if((out = fopen(optarg, "w")) == NULL) {
                                fprintf(stderr, "fopen(\"%s\", \"w\"): %s\n", optarg, strerror(errno));
                                exit(1);
                        }
                        break;
                case 'e':
                        switch(sscanf(optarg, "%" SCNu32 ":%" SCNu32, &eflag, &entry)) {
                        case 1:
                                entry = eflag;
                                linflag = 1;
                                eflag = 1;
                                segment = 0;
                                break;
                        case 2:
                                entry |= eflag << 16;
                                segflag = 1;
                                eflag = 1;
                                break;
                        default:
                                fprintf(stderr, "entry point parse error\n");
                                exit(1);
                        }
                        break;
                case 'c':
                        if(!sscanf(optarg, "%" SCNu32, &segment)) {
                                fprintf(stderr, "segment address parse error\n");
                                exit(1);
                        }
                        segflag = 1;
                        break;
                case 'h':
                case '?':
                        usage();
                        break;
                }
        }
        argc -= optind;
        argv += optind;

        if(argc) {
                in = fopen(argv[0], "r");
                if(in == NULL) {
                        fprintf(stderr, "fopen(\"%s\", \"r\"): %s\n", argv[0], strerror(errno));
                        exit(1);
                }
                ext = argv[0] + strlen(argv[0]);
                do {
                        ext--;
                } while((ext != argv[0]) && (*ext != '.'));
                ext++;
        } else usage();

        if(base && (buf = malloc(1024 * sizeof(uint8_t)))) {
                while(base)
                        base -= fread(buf, sizeof(uint8_t), base > 1024 ? 1024 : base, in);
                free(buf);
        }

        if(fmt) {
                for(bptr = binfmt; bptr->name; bptr++)
                        if(!strcmp(fmt, bptr->name))
                                break;
                if(!bptr->name) {
                        fprintf(stderr, "file format %s unknown\n", fmt);
                        exit(1);
                }
                
                if(!bptr->match(in))
                        notice("warning: file format %s not matched\n", fmt);
                /* 
                 *  match may have changed endian setting, reset it
                 *  same applies in and after the for loop below
                 */
                get_endian();
        } else  for(bptr = binfmt; get_endian(), bptr->name; bptr++)
                        if(bptr->match(in))
                                break;

        get_endian();

        if(!fmt && bptr->match == bin_match) {
                for(bptr = binfmt; bptr->name; bptr++)
                        if(!strcasecmp(ext, bptr->name) && bptr->match(in))
                                break;
                if(!bptr->name)
                        for(bptr = binfmt; bptr->match != bin_match; bptr++);
        }

        notice("input format: %s\n", bptr->descr);

        bptr->conv(in, out, addr);
        if(eflag) {
                if(segflag)
                        hexrecord(out, IH_SSTART, entry);
                else if(linflag)
                        hexrecord(out, IH_LSTART, entry);
        }
        hexrecord(out, IH_END);

        exit(0);
}
	  
void blkhex(FILE *out, uint8_t *buf, uint32_t len, uint32_t addr)
{
        uint32_t cnt=0;

        while(len) {
                cnt = (len > 16) ? 16 : len;
                hexrecord(out, IH_DATA, cnt, addr, buf);
                addr += cnt;
                buf += cnt;
                len -= cnt;
        }
}

void hexrecord(FILE *out, int type, ...)
{
        va_list ap;
        uint32_t sum=0, cnt=0, addr=0, i=0;
        uint8_t *ptr;
        
        va_start(ap, type);
        switch(type) {
        case IH_DATA: /* out, type, cnt, addr, buf */
                cnt  = va_arg(ap, uint32_t);
                addr = va_arg(ap, uint32_t);
                ptr  = va_arg(ap, uint8_t*);
                if(zero) {
                     for(i = sum = 0; i != cnt; i++)
                          sum += *(ptr+i);
                     if(!sum)
                          break;
                }
                sum  = cnt + (addr & 0xff) + ((addr>>8) & 0xff) + IH_DATA;
                fprintf(out, ":%.2" PRIX32 "%.4" PRIX32 "%.2X", cnt, addr & 0xffff, IH_DATA);
                for(i = 0; i != cnt; i++) {
                        sum += *ptr;
                        fprintf(out, "%.2X", *ptr++);
                }
                fprintf(out, "%.2" PRIX32 "\n", -sum & 0xff);
                break;
        case IH_END: /* out, type */
                fprintf(out, ":%.2X%.4X%.2X%.2X\n", 0, 0, IH_END, -IH_END & 0xff);
                break;
        case IH_SEGADDR: /* out, type, addr */
                addr = va_arg(ap, uint32_t);
                sum  = -(2 + IH_SEGADDR + (addr & 0xff) + ((addr>>8) & 0xff)) & 0xff;
                fprintf(out, ":%.2X%.4X%.2X%.4" PRIX32 "%.2" PRIX32 "\n", 2, 0, IH_SEGADDR, addr & 0xffff, sum);
                break;
        case IH_SSTART: /* out, type, seg|ofs */
                addr = va_arg(ap, uint32_t);
                sum  = -(4 + IH_SSTART + ((addr>>16) & 0xff) + ((addr>>24) & 0xff) + (addr & 0xff) + ((addr>>8) & 0xff)) & 0xff;
                fprintf(out, ":%.2X%.4X%.2X%.4" PRIX32 "%.4" PRIX32 "%.2" PRIX32 "\n", 4, 0, IH_SSTART, (addr>>16) & 0xffff, addr & 0xffff, sum);
                break;
        case IH_LINADDR: /* out, type, hiaddr */
                addr = va_arg(ap, uint32_t);
                sum  = -(2 + IH_LINADDR + (addr & 0xff) + ((addr>>8) & 0xff)) & 0xff;
                fprintf(out, ":%.2X%.4X%.2X%.4" PRIX32 "%.2" PRIX32 "\n", 2, 0, IH_LINADDR, addr & 0xffff, sum);
                break;
        case IH_LSTART: /* out, type, addr */
                addr = va_arg(ap, uint32_t);
                sum  = -(4 + IH_LSTART + (addr & 0xff) + ((addr>>8) & 0xff) + ((addr>>16) & 0xff) + ((addr>>24) & 0xff)) & 0xff;
                fprintf(out, ":%.2X%.4X%.2X%.8" PRIX32 "%.2" PRIX32 "\n", 4, 0, IH_LSTART, addr, sum);
                break;
        default:
                notice("unknown record type - %.2X\n", type); 
        }
}

int notice(const char *fmt, ...)
{
        va_list ap;
        va_start(ap, fmt);

        if(!quiet)
                return(vfprintf(stderr, fmt, ap));
        return(0);
}
