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
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

void bin2hex(FILE *in, FILE *out, uint32_t addr)
{
        uint8_t *buf = malloc(IH_BLKSIZE * sizeof(uint8_t));
        uint32_t len;

        if(buf == NULL) {
                fprintf(stderr, "failed to allocate %d bytes for buf\n", IH_BLKSIZE);
                exit(1);
        }

        if(!segment)
                segment = (addr>>4) & 0xf000;
        while(!feof(in)) {
                if(segflag) hexrecord(out, IH_SEGADDR, segment);
                else if(linflag) hexrecord(out, IH_LINADDR, (addr >> 16) & 0xffff);
                len = fread(buf, sizeof(uint8_t), IH_BLKSIZE - (addr & 0xffff), in);
                blkhex(out, buf, len, addr);
                addr += len;
                segment += 0x1000;
        }
}

int bin_match(FILE *in)
{
        return(1); /* any input file can be treated as flat binary */
}
