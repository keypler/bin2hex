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

#include "intel.h"
#include "endian.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>

struct exec {
        uint32_t a_midmag;
        uint32_t a_text;
        uint32_t a_data;
        uint32_t a_bss;
        uint32_t a_syms;
        uint32_t a_entry;
        uint32_t a_trsize;
        uint32_t a_drsize;
};

#define OMAGIC 0407
#define NMAGIC 0410
#define ZMAGIC 0413
#define QMAGIC 0314

#define EX_DYNAMIC 0x20

#define N_GETMAGIC(x) ((x).a_midmag & 0xffff)
#define N_GETMID(x)   (((x).a_midmag >> 16) & 0x3ff)
#define N_GETFLAG(x)  (((x).a_midmag >> 26) & 0x3f)

#define N_BADMAG(x) ((N_GETMAGIC(x) != OMAGIC) && (N_GETMAGIC(x) != NMAGIC) && (N_GETMAGIC(x) != ZMAGIC) && (N_GETMAGIC(x) != QMAGIC))

void endian_aout32(struct exec *hdr)
{
        if(system_endian) {
                hdr->a_midmag = byteswap32(hdr->a_midmag);
        }

        if(twiddle) {
                hdr->a_text   = byteswap32(hdr->a_text);
                hdr->a_data   = byteswap32(hdr->a_data);
                hdr->a_bss    = byteswap32(hdr->a_bss);
                hdr->a_syms   = byteswap32(hdr->a_syms);
                hdr->a_entry  = byteswap32(hdr->a_entry);
                hdr->a_trsize = byteswap32(hdr->a_trsize);
                hdr->a_drsize = byteswap32(hdr->a_drsize);
        }
}

void aout322hex(FILE *in, FILE *out, uint32_t addr)
{
        uint8_t *buf = malloc(IH_BLKSIZE * sizeof(uint8_t));
        uint32_t len, bsiz, ofs;
        struct exec hdr;

        if(buf == NULL) {
                fprintf(stderr, "failed to allocate %d bytes for buf\n", IH_BLKSIZE);
                exit(1);
        }

        len = fread(&hdr, sizeof(hdr), 1, in);
        if(!len) {
                fprintf(stderr, "failed to read a.out header\n");
                exit(1);
        }

        endian_aout32(&hdr);

        if(N_BADMAG(hdr))
                notice("warning: bad magic\n");

        if(N_GETFLAG(hdr) & EX_DYNAMIC)
                notice("warning: dynamically linked executable\n");

        if(N_GETMAGIC(hdr) == ZMAGIC)
                notice("warning: demand paged executable\n");

        notice("magic  : %o\n", N_GETMAGIC(hdr));
        notice("machine: %d\n", N_GETMID(hdr));
        notice("text   : %#x\n", hdr.a_text);
        notice("data   : %#x\n", hdr.a_data);
        notice("entry  : %#x\n", hdr.a_entry);

        if(!eflag) {
                entry = hdr.a_entry;
                eflag = 1;
        }

        if(!linflag && !segflag) {
                if(N_GETMAGIC(hdr) == OMAGIC) {
                        if(hdr.a_text + hdr.a_data > IH_BLKSIZE)
                                linflag = 1;
                        else segflag = 1;
                } else {
                        if(hdr.a_text > IH_BLKSIZE || hdr.a_data > IH_BLKSIZE)
                                linflag = 1;
                        else segflag = 1;
                }
        }

        while(!feof(in) && hdr.a_text) {
                if(segflag)
                        hexrecord(out, IH_SEGADDR, segment + ((addr>>4) & 0xf000));
                else if(linflag)
                        hexrecord(out, IH_LINADDR, (addr>>16) & 0xffff);

                len  = 0;
                ofs  = addr & 0x0ffff;
                bsiz = (hdr.a_text > IH_BLKSIZE ? IH_BLKSIZE : hdr.a_text);
                if(bsiz + ofs > IH_BLKSIZE) bsiz = IH_BLKSIZE - ofs;

                while(!feof(in) && bsiz) {
                        len = fread(buf, sizeof(uint8_t), bsiz, in);
                        blkhex(out, buf, len, ofs);
                        ofs  += len;
                        addr += len;
                        bsiz -= len;
                        hdr.a_text -= len;
                }
        }

        if(N_GETMAGIC(hdr) == NMAGIC) {
                if(segflag) {
                        addr += 0xf;
                        addr &= 0xfffffff0;
                } else if(linflag) {
                        addr += 0xfff;
                        addr &= 0xfffff000;
                }
        }

        while(!feof(in) && hdr.a_data) {
                if(segflag)
                        hexrecord(out, IH_SEGADDR, segment + ((addr>>4) & 0xf000));
                else if(linflag)
                        hexrecord(out, IH_LINADDR, (addr>>16) & 0xffff);

                len = 0;
                ofs = addr & 0x0ffff;
                bsiz = (hdr.a_data > IH_BLKSIZE ? IH_BLKSIZE : hdr.a_data);
                if(bsiz + ofs > IH_BLKSIZE) bsiz = IH_BLKSIZE - ofs;
                while(!feof(in) && bsiz) {
                        len = fread(buf, sizeof(uint8_t), bsiz, in);
                        blkhex(out, buf, len, ofs);
                        ofs  += len;
                        addr += len;
                        bsiz -= len;
                        hdr.a_data -= len;
                }
        }
}

int aout32_match(FILE *in)
{
        struct exec hdr;
        uint32_t len;
        fpos_t pos;

        fgetpos(in, &pos);
        len = fread(&hdr, sizeof(hdr), 1, in);
        fsetpos(in, &pos);

        if(!len)
                return(0);

        endian_aout32(&hdr);

        if(N_BADMAG(hdr))
                return(0);

        if(N_GETFLAG(hdr) & EX_DYNAMIC)
                return(0);

        if(N_GETMAGIC(hdr) == ZMAGIC)
                return(0);

        return(1);
}
