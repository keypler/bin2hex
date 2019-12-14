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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>

#define EI_CLASS      4
#define EI_DATA       5
#define EI_VERSION    6
#define EI_OSABI      7
#define EI_ABIVERSION 8

#define ELFCLASS32    1
#define ELFCLASS64    2

#define ELFDATA2LSB   1
#define ELFDATA2MSB   2

#define EV_CURRENT    1

#define ET_NONE       0
#define ET_REL        1
#define ET_EXEC       2
#define ET_DYN        3
#define ET_CORE       4
#define ET_NUM        5

#define PT_LOAD       1
#define PF_R          4
#define PF_W          2
#define PF_X          1

#define ELFOSABI_ARM         97
#define ELFOSABI_STANDALONE 255


#define MAX_ELFIDENT 16
typedef struct {
        uint8_t  e_ident[MAX_ELFIDENT];
        uint16_t e_type;
        uint16_t e_machine;
        uint32_t e_version;
        uint32_t e_entry;
        uint32_t e_phoff;
        uint32_t e_shoff;
        uint32_t e_flags;
        uint16_t e_ehsize;
        uint16_t e_phentsize;
        uint16_t e_phnum;
        uint16_t e_shentsize;
        uint16_t e_shnum;
        uint16_t e_shstrndx;
} Elf32_Ehdr;

typedef struct {
        uint32_t p_type;
        uint32_t p_offset;
        uint32_t p_vaddr;
        uint32_t p_paddr;
        uint32_t p_filesz;
        uint32_t p_memsz;
        uint32_t p_flags;
        uint32_t p_align;
} Elf32_Phdr;


#define MAX_ELFOSABI 15
const char *elfosabi[MAX_ELFOSABI] = {
        "UNIX System V",
        "HP-UX",
        "NetBSD",
        "GNU/Linux",
        "GNU/Hurd",
        "86Open",
        "Solaris",
        "Monterey",
        "IRIX",
        "FreeBSD",
        "Tru64 Unix",
        "Novell Modesto",
        "OpenBSD"
        "OpenVMS",
        "HP Nonstop-UX",
        "Amiga Research OS",
};

#define MAX_ELFMACHINE 110
const char *elfmachine[MAX_ELFMACHINE] = {
        "none",
        "AT&T WE 32100",
        "SPARC",
        "Intel 80386",
        "Motorola 68000",
        "Motorola 88000",
        "Intel 80486",
        "Intel 80860",
        "MIPS I",
        "IBM System/370",
        "MIPS RS3000 Little-Endian",
        "IBM RS/6000",
        "reserved", "reserved", "reserved",
        "HP PA-RISC",
        "NCube",
        "Fujitsu VPP500",
        "Enhanced Instruction Set SPARC",
        "Intel 80960",
        "PowerPC",
        "64bit PowerPC",
        "IBM System/390",
        "reserved", "reserved", "reserved", "reserved",
        "reserved", "reserved", "reserved", "reserved",
        "reserved", "reserved", "reserved", "reserved",
        "reserved",
        "NEC V800",
        "Fujitsu FR20",
        "TRW RH-32",
        "Motorola RCE",
        "Advanced Risc Machines ARM",
        "Digital Equipment Corp. Alpha",
        "Hitachi Super-H",
        "SPARC Version 9",
        "Siemens Tricore",
        "Argonaut RISC",
        "Hitachi H8/300",
        "Hitachi H8/300H",
        "Hitachi H8S",
        "Hitachi H8/500",
        "Intel Itanium",
        "Stanford MIPS-X",
        "Motorola Coldfire",
        "Motorola MC68HC12",
        "Fujitsu MMA Multimedia Accelerator",
        "Siemens PCP",
        "Sony nCPU embedded RISC",
        "Denso NDR1",
        "Motorola Star*Core",
        "Toyota ME16",
        "STMicroelectronics ST100",
        "Advance Logic Corp. TinyJ",
        "AMD x86-64",
        "Sony DSP",
        "Digital Equipment Corp. PDP-10",
        "Digital Equipment Corp. PDP-11",
        "Siemens FX66",
        "STMicroelectronics ST9+",
        "STMicroelectronics ST7",
        "Motorola MC68HC16",
        "Motorola MC68HC11",
        "Motorola MC68HC08",
        "Motorola MC68HC05",
        "Silicon Graphics SVx",
        "STMicroelectronics ST19",
        "Digital Equipment Corp. VAX",
        "Axis Communications 32bit embedded CPU",
        "Infineon Technologies 32bit embedded CPU",
        "Element 14 64bit DSP",
        "LSI Logic 16bit DSP",
        "Don Knuths MMIX",
        "Harvard Machine-Independent",
        "SiTera Prism",
        "Atmel AVR",
        "Fujitsu FR30",
        "Mitsubishi D10V",
        "Mitsubishi D30V",
        "NEC v850",
        "Mitsubishi M32R",
        "Matsushita MN10300",
        "Matsushita MN10200",
        "picoJava",
        "OpenRISC",
        "ARC Cores Tangent-A5",
        "Tensilica Xtensa",
        "Alphamosaic VideoCore",
        "Thompson Multimedia General Purpose Processor",
        "National Semiconductor 32000",
        "Tenor Network TPC",
        "STMicroelectronics ST200",
        "Ubicom IP2xxx",
        "MAX"
        "National Semiconductor CompactRISC",
        "Fujitsu F2MC16",
        "Texas Instruments msp430",
        "Analog Devices Blackfin DSP",
        "Seiko Epson S1C33",
        "Sharp embedded microprocessor",
        "Arca RISC",
        "Unicore",
};

#define MAX_PT_NUM 8
const char *phdr_type[MAX_PT_NUM] = {
        "unused",
        "loadable program segment",
        "dynamic linking information",
        "program interpreter",
        "auxiliary information",
        "shared library",
        "header table",
        "thread local storage",
};

void endian_ehdr(Elf32_Ehdr *hdr)
{
        if(system_endian) {
                hdr->e_type      = byteswap16(hdr->e_type);
                hdr->e_machine   = byteswap16(hdr->e_machine);
                hdr->e_version   = byteswap32(hdr->e_version);
                hdr->e_entry     = byteswap32(hdr->e_entry);
                hdr->e_phoff     = byteswap32(hdr->e_phoff);
                hdr->e_shoff     = byteswap32(hdr->e_shoff);
                hdr->e_flags     = byteswap32(hdr->e_flags);
                hdr->e_ehsize    = byteswap16(hdr->e_ehsize);
                hdr->e_phentsize = byteswap16(hdr->e_phentsize);
                hdr->e_phnum     = byteswap16(hdr->e_phnum);
                hdr->e_shentsize = byteswap16(hdr->e_shentsize);
                hdr->e_shnum     = byteswap16(hdr->e_shnum);
                hdr->e_shstrndx  = byteswap16(hdr->e_shstrndx);
        }
}

void endian_phdr(Elf32_Phdr *hdr)
{
        if(system_endian) {
                hdr->p_type   = byteswap32(hdr->p_type);
                hdr->p_offset = byteswap32(hdr->p_offset);
                hdr->p_vaddr  = byteswap32(hdr->p_vaddr);
                hdr->p_paddr  = byteswap32(hdr->p_paddr);
                hdr->p_filesz = byteswap32(hdr->p_filesz);
                hdr->p_memsz  = byteswap32(hdr->p_memsz);
                hdr->p_flags  = byteswap32(hdr->p_flags);
                hdr->p_align  = byteswap32(hdr->p_align);
        }
}

void elf2hex(FILE *in, FILE *out, uint32_t addr)
{
        uint32_t len, i, null;
        Elf32_Ehdr hdr;
        Elf32_Phdr *phdr;

        if(segflag) {
                notice("warning: segflag set, resetting\n");
                segflag = 0;
        }

        linflag = 1;

        len = fread(&hdr, sizeof(hdr), 1, in);
        fseek(in, -sizeof(hdr), SEEK_CUR);

        if(!len) {
                fprintf(stderr, "failed to read ELF header\n");
                exit(1);
        }

        if(memcmp(hdr.e_ident, "\177ELF", 4))
                notice("warning: bad magic\n");

        notice("ELF magic:\t\t\t%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n",
               hdr.e_ident[0], hdr.e_ident[1], hdr.e_ident[2], hdr.e_ident[3],
               hdr.e_ident[4], hdr.e_ident[5], hdr.e_ident[6], hdr.e_ident[7],
               hdr.e_ident[8], hdr.e_ident[9], hdr.e_ident[10], hdr.e_ident[11],
               hdr.e_ident[12], hdr.e_ident[13], hdr.e_ident[14], hdr.e_ident[15]);
        
        switch(hdr.e_ident[EI_CLASS]) {
        case ELFCLASS32:
                notice("ELF class:\t\t\t32 bit\n");
                break;
        case ELFCLASS64:
                notice("ELF class:\t\t\t64bit (warning: unsupported)\n");
                break;
        default:
                notice("warning: unknown ELF class %d\n", hdr.e_ident[EI_CLASS]);
                break;
        }

        switch(hdr.e_ident[EI_DATA]) {
        case ELFDATA2LSB:
                set_endian(ENDIAN_LITTLE);
                notice("ELF data encoding:\t\t2's complement LSB first\n");
                break;
        case ELFDATA2MSB:
                set_endian(ENDIAN_BIG);
                notice("ELF data encoding:\t\t2's complement MSB first\n");
                break;
        default:
                notice("warning: unknown ELF data encoding %d\n", hdr.e_ident[EI_CLASS]);
                break;
        }

        if(hdr.e_ident[EI_VERSION] == EV_CURRENT)
                notice("ELF version:\t\t\t%d (current)\n", hdr.e_ident[EI_VERSION]);
        else {
                notice("warning: unknown ELF version %d\n", hdr.e_ident[EI_VERSION]);
        }
        
        if(hdr.e_ident[EI_OSABI] < MAX_ELFOSABI)
                notice("ELF OS ABI:\t\t\t%s\n", elfosabi[hdr.e_ident[EI_OSABI]]);
        else switch(hdr.e_ident[EI_OSABI]) {
        case ELFOSABI_ARM:
                notice("ELF OS ABI:\t\t\tARM\n");
                break;
        case ELFOSABI_STANDALONE:
                notice("ELF OS ABI:\t\t\tstandalone/embedded application\n");
                break;
        default:
                notice("warning: unknown ELF OS ABI %d\n", hdr.e_ident[EI_OSABI]);
        }
        
        notice("ELF ABI Version:\t\t%d\n", hdr.e_ident[EI_ABIVERSION]);

        endian_ehdr(&hdr);

        notice("ELF file type:\t\t\t");
        switch(hdr.e_type) {
        case ET_NONE:
                notice("none");
                break;
        case ET_REL:
                notice("relocatable");
                break;
        case ET_EXEC:
                notice("executable");
                break;
        case ET_DYN:
                notice("shared object");
                break;
        case ET_CORE:
                notice("core dump");
                break;
        default:
                notice("unknown - %d", hdr.e_type);
        }
        notice("\n");
        
        if(hdr.e_machine < MAX_ELFMACHINE)
                notice("ELF machine:\t\t\t%s\n", elfmachine[hdr.e_machine]);
        else    notice("ELF machine:\t\t\treserved (%d)\n", hdr.e_machine);

        notice("ELF entry point:\t\t%#x\n", hdr.e_entry);
        notice("ELF program header offset:\t%d\n", hdr.e_phoff);
        notice("ELF section header offset:\t%d\n", hdr.e_shoff);
        notice("ELF processor specific flags:\t0x%x\n", hdr.e_flags);
        notice("ELF header size:\t\t%d\n", hdr.e_ehsize);
        notice("ELF program header entry size:\t%d\n", hdr.e_phentsize);
        notice("ELF program header entries:\t%d\n", hdr.e_phnum);
        notice("ELF section header entry size:\t%d\n", hdr.e_shentsize);
        notice("ELF section header entries:\t%d\n", hdr.e_shnum);
        notice("ELF string section index:\t%d\n", hdr.e_shstrndx);

        if(fseek(in, hdr.e_phoff, SEEK_CUR) == -1) {
                fprintf(stderr, "failed to seek program header: %s\n", strerror(errno));
                exit(1);
        }

        phdr = calloc(sizeof(Elf32_Phdr), hdr.e_phnum);

        for(len = 0; !feof(in) && len != hdr.e_phnum; len += fread(phdr+len, sizeof(Elf32_Phdr), hdr.e_phnum-len, in));
        if(len != hdr.e_phnum)
                notice("warning: failed to read all program headers\n");

        fseek(in, -(hdr.e_phoff + len*hdr.e_phentsize), SEEK_CUR);
        null = ftell(in);

        for(i = 0; i != len; i++) {
                uint32_t cnt=0, ofs=0;
                uint8_t buf[IH_BLKSIZE];
                endian_phdr(&phdr[i]);
                notice("\n");
                notice("Program Header, Segment Entry: \t%d\n", i);
                if(phdr[i].p_type < MAX_PT_NUM)
                        notice("Segment type:\t\t\t%s\n", phdr_type[phdr[i].p_type]);
                else    notice("Segment type:\t\t\tunknown (%#x)\n", phdr[i].p_type);
                if(phdr[i].p_type) {
                        notice("Segment offset:\t\t\t%#x\n", phdr[i].p_offset);
                        notice("Segment virtual address:\t%#x\n", phdr[i].p_vaddr);
                        notice("Segment physical address:\t%#x\n", phdr[i].p_paddr);
                        notice("Segment file size:\t\t%#x\n", phdr[i].p_filesz);
                        notice("Segment memory size:\t\t%#x\n", phdr[i].p_memsz);
                        notice("Segment flags:\t\t\t%c%c%c\n", 
                               (phdr[i].p_flags & PF_R) ? 'r' : '-', 
                               (phdr[i].p_flags & PF_W) ? 'w' : '-', 
                               (phdr[i].p_flags & PF_X) ? 'x' : '-');
                        notice("Segment alignment:\t\t%#x\n", phdr[i].p_align);
                }
                if(phdr[i].p_type != PT_LOAD) {
                        notice("(Segment not loadable, ignored)\n");
                        continue;
                }

                if(fseek(in, phdr[i].p_offset, SEEK_CUR) == -1) {
                        fprintf(stderr, "failed to seek program segment: %s\n", strerror(errno));
                        exit(1);
                }
                phdr[i].p_paddr += addr;
                while(!feof(in) && phdr[i].p_filesz) {
                        hexrecord(out, IH_LINADDR, (phdr[i].p_paddr>>16) & 0xffff);
                        cnt  = phdr[i].p_filesz > IH_BLKSIZE ? IH_BLKSIZE - (phdr[i].p_paddr & 0xffff) : phdr[i].p_filesz;
                        while(!feof(in) && (cnt -= ofs))
                                ofs += fread(buf+ofs, sizeof(uint8_t), cnt, in);
                        blkhex(out, buf, ofs, phdr[i].p_paddr & 0xffff);
                        phdr[i].p_filesz -= ofs;
                        phdr[i].p_memsz  -= ofs;
                        phdr[i].p_paddr  += ofs;
                        ofs = 0;
                }
                if(zero)
                        continue;

                memset(buf, 0, IH_BLKSIZE);
                while(phdr[i].p_memsz) {
                        hexrecord(out, IH_LINADDR, (phdr[i].p_paddr>>16) & 0xffff);
                        cnt  = phdr[i].p_memsz > IH_BLKSIZE ? IH_BLKSIZE - (phdr[i].p_paddr & 0xffff) : phdr[i].p_memsz;
                        blkhex(out, buf, cnt, phdr[i].p_paddr & 0xffff);
                        phdr[i].p_memsz -= cnt;
                        phdr[i].p_paddr += cnt;
                }
                fseek(in, null, SEEK_SET);
        }
        if(!eflag)
                hexrecord(out, IH_LSTART, hdr.e_entry + addr);
}

int elf_match(FILE *in)
{
        uint32_t len;
        fpos_t pos;
        Elf32_Ehdr hdr;

        if(segflag)
                return(0);

        fgetpos(in, &pos);
        len = fread(&hdr, sizeof(hdr), 1, in);
        fsetpos(in, &pos);


        if(!len) return(0);

        if(memcmp(hdr.e_ident, "\177ELF", 4))
                return(0);

        if(hdr.e_ident[EI_CLASS] != ELFCLASS32)
                return(0);

        switch(hdr.e_ident[EI_DATA]) {
        case ELFDATA2LSB:
                set_endian(ENDIAN_LITTLE);
                break;
        case ELFDATA2MSB:
                set_endian(ENDIAN_BIG);
                break;
        default:
                return(0);
        }

        if(hdr.e_ident[EI_VERSION] != EV_CURRENT)
                return(0);

        endian_ehdr(&hdr);

        if(hdr.e_type != ET_EXEC)
                return(0);

        if(!hdr.e_phoff)
                return(0);

        return(1);
}

