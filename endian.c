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
#include <inttypes.h>
#include <string.h>

uint32_t system_endian;
uint32_t twiddle;

uint16_t twiddle16(uint16_t data)
{
        return(twiddle ? byteswap16(data) : data);
}

uint32_t twiddle32(uint32_t data)
{
        return(twiddle ? byteswap32(data) : data);
}

uint16_t byteswap16(uint16_t data)
{
        data &= 0xffff;
        return(((data >> 8) & 0xff) | ((data << 8) & 0xff00));
}

uint32_t byteswap32(uint32_t data)
{
        data &= 0xffffffff;
        return((byteswap16(data >> 16) & 0xffff) |  ((byteswap16(data) << 16) & 0xffff0000));
}

void get_endian(void)
{
        int i = 1;
        system_endian = ((char *) &i)[0];
}

void set_endian(uint32_t endian)
{
        system_endian ^= endian;
}
