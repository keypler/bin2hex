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

void com2hex(FILE *in, FILE *out, uint32_t addr)
{
        uint8_t *buf = malloc(IH_BLKSIZE * sizeof(uint8_t));
        uint32_t len, bsiz = 0;

        if(buf == NULL) {
                fprintf(stderr, "failed to allocate %d bytes for buf\n", IH_BLKSIZE);
                exit(1);
        }

        if(linflag)
                notice("warning: linear address records requested for .COM executable\n");

        if(!segflag) {
                segment = 0x0100;
                segflag = 1;
        }

        if(!eflag) {
                entry = 0x01000100;
                eflag = 1;
        }
        
        hexrecord(out, IH_SEGADDR, segment);

        bsiz = addr & 0xffff;
        while(!feof(in) && bsiz < 0x10000) {
                len = fread(buf, sizeof(uint8_t), IH_BLKSIZE - (addr & 0xffff), in);
                blkhex(out, buf, len, addr);
                bsiz += len;
        }
}

int com_match(FILE *in)
{
        if(linflag)
                return(0);

        return(1); /* any input file can be treated as .COM flat binary */
}
