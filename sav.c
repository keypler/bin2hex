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
#include <sys/stat.h>
#include <errno.h>
#include <inttypes.h>

#define BLKSIZE  512
#define BMAPSIZE 128

void sav2hex(FILE *in, FILE *out, uint32_t addr)
{
        uint8_t *buf = calloc(BLKSIZE, sizeof(uint8_t));
        uint8_t bmap[BMAPSIZE];
        uint32_t len=0;
        uint16_t start, stack, status, limit, vir, rel, i;
        struct stat sb;

        if(buf == NULL) {
                fprintf(stderr, "failed to allocate %d bytes for buf\n", BLKSIZE);
                exit(1);
        }

        while(!feof(in) && len != BLKSIZE)
                len += fread(buf+len, sizeof(uint8_t), BLKSIZE-len, in);

        addr += len;

        if(fstat(fileno(in), &sb) == -1) {
                fprintf(stderr, "fstat(in) failed: %s\n", strerror(errno));
                exit(1);
        }

        vir    = buf[1]*256 + buf[0];
        start  = buf[041]*256 + buf[040]; 
        stack  = buf[043]*256 + buf[042]; 
        status = buf[045]*256 + buf[044];
        limit  = buf[051]*256 + buf[050];
        rel    = buf[061]*256 + buf[060];

        notice("file size    : %d\n", sb.st_size);
        notice("high limit   : %.6o (%d)\n", limit, limit);
        notice("start address: %.6o\n", start);
        notice("stack address: %.6o\n", stack);
        notice("status word  : %.6o\n", status);
        
        if(sb.st_size < limit + 2)
                notice("warning: file shorter than high limit\n");

        if(start > limit)
                notice("warning: start address higher than high limit\n");

        if(status)
                notice("warning: overlaid executable\n");

        if(vir == 37178)
                notice("warning: virtual executable\n");

        if(rel == 29012)
                notice("warning: relocatable executable\n");

        for(i = 0; i != BMAPSIZE; i++)
                bmap[i] = (buf[0360 + (i>>3)] & (1<<(7-(i&7)))) != 0;

        i = 1; limit += 2; limit -= 01000;
        while(!feof(in) && limit) {
                len = 0;
                while(!feof(in) && limit && len != (limit > BLKSIZE ? BLKSIZE : limit))
                        len += fread(buf+len, sizeof(uint8_t), (limit > BLKSIZE ? BLKSIZE : limit) - len, in);
                if(bmap[i++])
                        blkhex(out, buf, len, addr);
                addr  += len;
                limit -= len;
        }
}

int sav_match(FILE *in)
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
                return(0);

        return(1);
}
