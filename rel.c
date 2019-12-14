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
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <inttypes.h>

#define BLKSIZE  512
#define BMAPSIZE 128

void rel2hex(FILE *in, FILE *out, uint32_t addr)
{
        uint8_t *buf = calloc(IH_BLKSIZE, sizeof(uint8_t));
        uint8_t bmap[BMAPSIZE];
        uint32_t len=0, rflag=0;
        uint16_t start, stack, status, limit, vir, rel, rsize, ssize, rblock, i;

        if(buf == NULL) {
                fprintf(stderr, "failed to allocate %d bytes for buf\n", IH_BLKSIZE);
                exit(1);
        }

        while(!feof(in) && len != IH_BLKSIZE)
                len += fread(buf+len, sizeof(uint8_t), IH_BLKSIZE-len, in);

        vir    = buf[1]*256 + buf[0];
        start  = buf[041]*256 + buf[040]; 
        stack  = buf[043]*256 + buf[042]; 
        status = buf[045]*256 + buf[044];
        limit  = buf[051]*256 + buf[050];
        rsize  = buf[053]*256 + buf[052];
        ssize  = buf[055]*256 + buf[054];
        rel    = buf[061]*256 + buf[060];
        rblock = buf[063]*256 + buf[062];
        rblock *= 512;

        notice("file size    : %d\n", len);
        notice("high limit   : %.6o (%d)\n", limit, limit);
        notice("root size    : %.6o (%d)\n", rsize, rsize);
        notice("start address: %.6o\n", start);
        notice("stack address: %.6o\n", stack);
        notice("stack size   : %.6o\n", ssize);
        notice("status word  : %.6o\n", status);
        notice("reloc start  : %.6o (%d)\n", rblock, rblock);
        
        if(len < limit + 2)
                notice("warning: file shorter than high limit\n");

        if(start > limit)
                notice("warning: start address higher than high limit\n");

        if(status)
                notice("warning: overlaid executable\n");

        if(vir == 37178)
                notice("warning: virtual executable\n");

        if(rel != 29012)
                notice("warning: not a relocatable executable\n");

        if(addr) {
                uint32_t sub=0, j=rblock;
                uint16_t offset=0, orig=0, data=0, new=0;
                
                while((buf[j] + buf[j+1]*256) != 0177776) {
                        offset = buf[j] + buf[j+1]*256;
                        data   = buf[j+2] + buf[j+3]*256;
                        sub    = offset & 0100000;
                        offset &= 077777;
                        offset *= 2;
                        offset += 01000;
                        orig   = buf[offset] + buf[offset+1]*256;
                        new    = sub ? orig - addr + 01000 : orig + addr - 01000;
                        if(orig != data)
                                notice("warning: relocating location %.6o, found %.6o, expected %.6o\n", offset, orig, data);
                        buf[offset]   = new & 0377;
                        buf[offset+1] = (new / 256) & 0377;
                        j += 4;
                }
                addr -= 01000;
                rflag = 1;
        } else  blkhex(out, buf, BLKSIZE, addr);

        for(i = 0; i != BMAPSIZE; i++)
                bmap[i] = (buf[0360 + (i>>3)] & (1<<(7-(i&7)))) != 0;

        i = 1; limit += 2; limit -= 01000; addr += 01000;
        while(limit) {
                if(bmap[i++])
                        blkhex(out, buf+BLKSIZE*(i-1), limit > BLKSIZE ? BLKSIZE : limit, addr);
                addr  += limit > BLKSIZE ? BLKSIZE : limit;
                limit -= limit > BLKSIZE ? BLKSIZE : limit;
        }

        if(!rflag)
                for(i = 0; buf[rblock+i] + buf[rblock+i+1]*256 != 0177776; i += 4); 
                blkhex(out, buf+rblock, i+2, rblock);
}

int rel_match(FILE *in)
{
        uint8_t *buf = calloc(BLKSIZE, sizeof(uint8_t));
        uint32_t len=0;
        uint16_t start, status, limit, vir, rel;
        struct stat sb;

        if(buf == NULL) {
                fprintf(stderr, "failed to allocate %d bytes for buf\n", BLKSIZE);
                exit(1);
        }

        while(!feof(in) && len != BLKSIZE)
                len += fread(buf+len, sizeof(uint8_t), BLKSIZE-len, in);

        fseek(in, -len, SEEK_CUR);

        if(len < BLKSIZE)
                return(0);

        if(fstat(fileno(in), &sb) == -1) {
                fprintf(stderr, "fstat(in) failed: %s\n", strerror(errno));
                exit(1);
        }

        vir    = buf[1]*256 + buf[0];
        start  = buf[041]*256 + buf[040]; 
        status = buf[045]*256 + buf[044];
        limit  = buf[051]*256 + buf[050];
        rel    = buf[061]*256 + buf[060];

        if(sb.st_size < limit + 2)
                return(0);

        if(start > limit)
                return(0);

        if(status)
                return(0);

        if(vir == 37178)
                return(0);

        if(rel == 29012)
                return(1);

        return(0);
}
