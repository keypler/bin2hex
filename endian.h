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

#ifndef __ENDIAN_H
#define __ENDIAN_H

#include <inttypes.h>

extern uint32_t system_endian;
extern uint32_t twiddle;

uint16_t twiddle16(uint16_t data);
uint32_t twiddle32(uint32_t data);
uint16_t byteswap16(uint16_t data);
uint32_t byteswap32(uint32_t data);
void get_endian(void);
void set_endian(uint32_t endian);

#define ENDIAN_BIG    0
#define ENDIAN_LITTLE 1

#endif /* __ENDIAN_H */
