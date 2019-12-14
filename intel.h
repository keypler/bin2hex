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

#ifndef __INTEL_H
#define __INTEL_H

#define IH_DATA    0
#define IH_END     1
#define IH_SEGADDR 2
#define IH_SSTART  3
#define IH_LINADDR 4
#define IH_LSTART  5

#define IH_BLKSIZE 65536

extern void intel();

#endif /* __INTEL_H */
