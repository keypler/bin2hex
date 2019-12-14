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
#include <inttypes.h>

struct exec {
        int16_t a_magic;
        uint16_t a_text;
        uint16_t a_data;
        uint16_t a_bss;
        uint16_t a_syms;
        uint16_t a_entry;
        uint16_t a_unused;
        uint16_t a_flag;
};

#define OMAGIC 0407
#define NMAGIC 0410
#define IMAGIC 0411
#define VMAGIC1 0405
#define VMAGIC2 0430
#define VMAGIC3 0431

void twiddle_hdr(struct exec *hdr)
{
        if(twiddle) {
                hdr->a_magic  = byteswap16(hdr->a_magic);
                hdr->a_text   = byteswap16(hdr->a_text);
                hdr->a_data   = byteswap16(hdr->a_data);
                hdr->a_bss    = byteswap16(hdr->a_bss);
                hdr->a_syms   = byteswap16(hdr->a_syms);
                hdr->a_entry  = byteswap16(hdr->a_entry);
                hdr->a_unused = byteswap16(hdr->a_unused);
                hdr->a_flag   = byteswap16(hdr->a_flag);
        }
}

void aout162hex(FILE *in, FILE *out, uint32_t addr)
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

        twiddle_hdr(&hdr);

        switch(hdr.a_magic) {
        case OMAGIC:
        case NMAGIC:
                break;
        case IMAGIC:
                notice("warning: separate executable\n");
                break;
        case VMAGIC1:
        case VMAGIC2:
        case VMAGIC3:
                notice("warning: overlaid executable\n");
                break;
        default:
                notice("warning: bad magic\n");
        }

        notice("magic  : %o\n", hdr.a_magic);
        notice("text   : %#x\n", hdr.a_text);
        notice("data   : %#x\n", hdr.a_data);
        notice("entry  : %#x (ignored)\n", hdr.a_entry);

        while(!feof(in) && hdr.a_text) {
                len  = 0;
                ofs  = addr & 0x0ffff;
                bsiz = hdr.a_text;
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

        if(hdr.a_magic == NMAGIC) {
                addr += 0x3f;
                addr &= 0xffffffc0;
        }
        
        while(!feof(in) && hdr.a_data) {
                len = 0;
                ofs = addr & 0x0ffff;
                bsiz = hdr.a_data;
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

int aout16_match(FILE *in)
{
        struct exec hdr;
        uint32_t len;
        fpos_t pos;

        fgetpos(in, &pos);
        len = fread(&hdr, sizeof(hdr), 1, in);
        fsetpos(in, &pos);

        if(!len)
                return(0);

        switch(twiddle16(hdr.a_magic)) {
        case OMAGIC:
        case NMAGIC:
                break;
        case IMAGIC:
        case VMAGIC1:
        case VMAGIC2:
        case VMAGIC3:
        default:
                return(0);
        }

        return(1);
}
