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

#ifndef __BIN2HEX_H
#define __BIN2HEX_H

#include <stdio.h>
#include <inttypes.h>

#define BINDECL(fmt) \
extern void fmt ## 2hex(FILE *in, FILE *out, uint32_t addr); \
extern int fmt ## _match(FILE *in)

#define BINFMT(fmt, descr) { #fmt, descr, fmt ## 2hex, fmt ## _match }

extern struct binfmt {
        char *name;
        char *descr;
        void (*conv)(FILE *in, FILE *out, uint32_t addr);
        int (*match)(FILE *in);
} binfmt[];

extern uint32_t quiet;
extern uint32_t zero;
extern uint32_t entry;
extern uint32_t eflag;
extern uint32_t segment;
extern uint32_t segflag;
extern uint32_t linflag;

void blkhex(FILE *out, uint8_t *buf, uint32_t len, uint32_t addr);
void hexrecord(FILE *out, int type, ...);
int notice(const char *fmt, ...);

BINDECL(aout16);
BINDECL(aout32);
BINDECL(elf);
BINDECL(exe);
BINDECL(bin);
BINDECL(com);
BINDECL(sav);
BINDECL(rel);

#endif /* __BIN2HEX_H */
