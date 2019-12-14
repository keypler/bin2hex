#include "bin2hex.h"
#include "endian.h"
#include "intel.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

struct exe_hdr {
        uint16_t e_magic;  /* MZ bzw. 0x5a4d */
        uint16_t e_seclen; /* % 512          */
        uint16_t e_filesz; /* * 512          */
        uint16_t e_nreloc;
        uint16_t e_hdrsz;  /* * 16           */
        uint16_t e_minpar; /* * 16           */
        uint16_t e_maxpar; /* * 16           */
        uint16_t e_stkseg; /* * 16           */
        uint16_t e_stkptr;
        uint16_t e_chksum;
        uint16_t e_entry;
        uint16_t e_code;   /* * 16           */
        uint16_t e_reloc;
        uint16_t e_ovrlay;
};

void endian_exehdr(struct exe_hdr *hdr)
{
        if(system_endian) {
                hdr->e_magic  = byteswap16(hdr->e_magic);
                hdr->e_seclen = byteswap16(hdr->e_seclen);
                hdr->e_filesz = byteswap16(hdr->e_filesz);
                hdr->e_nreloc = byteswap16(hdr->e_nreloc);
                hdr->e_hdrsz  = byteswap16(hdr->e_hdrsz);
                hdr->e_minpar = byteswap16(hdr->e_minpar);
                hdr->e_maxpar = byteswap16(hdr->e_maxpar);
                hdr->e_stkseg = byteswap16(hdr->e_stkseg);
                hdr->e_chksum = byteswap16(hdr->e_chksum);
                hdr->e_entry  = byteswap16(hdr->e_entry);
                hdr->e_code   = byteswap16(hdr->e_code);
                hdr->e_reloc  = byteswap16(hdr->e_reloc);
                hdr->e_ovrlay = byteswap16(hdr->e_ovrlay);
        }
}

void exe2hex(FILE *in, FILE *out, uint32_t addr)
{
        uint8_t *buf = malloc(IH_BLKSIZE * sizeof(uint8_t));
        uint32_t len;
        struct exe_hdr hdr;
        fpos_t pos;

        if(buf == NULL) {
                fprintf(stderr, "failed to allocate %d bytes for buf\n", IH_BLKSIZE);
                exit(1);
        }

        set_endian(ENDIAN_LITTLE);

        fgetpos(in, &pos);
        len = fread(&hdr, sizeof(hdr), 1, in);
        fsetpos(in, &pos);

        if(!len) {
                perror("could not read .EXE header");
                exit(1);
        }

        endian_exehdr(&hdr);

        if(hdr.e_magic != 0x5a4d)
                notice("warning: bad magic\n");
        
        if(linflag)
                notice("warning: linear address records requested for .EXE executable\n");

        notice("Magic             : %#x, %c%c\n", hdr.e_magic, hdr.e_magic & 0xff, (hdr.e_magic >> 8) & 0xff);
        notice("last sector length: %#x\n", hdr.e_seclen);
        notice("file size         : %#x (%d)\n", hdr.e_filesz, (hdr.e_filesz - (hdr.e_seclen ? 1 : 0)) * 512 + hdr.e_seclen);
        notice("relocations       : %#x (%d)\n", hdr.e_nreloc, hdr.e_nreloc);
        notice("header size       : %#x (%d)\n", hdr.e_hdrsz, hdr.e_hdrsz);
        notice("min paragraphs    : %#x (%d)\n", hdr.e_minpar, hdr.e_minpar);
        notice("max paragraphs    : %#x (%d)\n", hdr.e_maxpar, hdr.e_maxpar);
        notice("stack segment     : %#x\n", hdr.e_stkseg);
        notice("stack pointer     : %#x\n", hdr.e_stkptr);
        notice("checksum          : %#x\n", hdr.e_chksum);
        notice("entry point       : %#x\n", hdr.e_entry);
        notice("code segment      : %#x\n", hdr.e_code);
        notice("relocation offset : %#x\n", hdr.e_reloc);
        notice("overlay number    : %d\n", hdr.e_ovrlay);

        if(fseek(in, hdr.e_hdrsz * 16, SEEK_CUR) == -1) {
                perror("failed to seek to .EXE data");
                exit(1);
        }

        if(!segment)
                segment = (addr>>4) & 0xf000;

        if(!segflag)
                segflag = 1;

        if(!segment)
                segment = 0x0100;

        if(!eflag) {
                entry = ((hdr.e_code + segment) << 16) | hdr.e_entry;
                eflag = 1;
        }

        while(!feof(in)) {
                hexrecord(out, IH_SEGADDR, segment);
                len = fread(buf, sizeof(uint8_t), IH_BLKSIZE - (addr & 0xffff), in);
                blkhex(out, buf, len, addr);
                addr += len;
                segment += 0x1000;
        }
}

int exe_match(FILE *in)
{
        uint32_t len;
        fpos_t pos;
        struct exe_hdr hdr;

        set_endian(ENDIAN_LITTLE);

        fgetpos(in, &pos);
        len = fread(&hdr, sizeof(hdr), 1, in);
        fsetpos(in, &pos);

        endian_exehdr(&hdr);
        
        if(!len) return(0);
        
        if(hdr.e_magic != 0x5a4d  && hdr.e_magic != 0x4d5a)
                return(0);

        return(1);
}
