#include <elf.h>

#include <stdio.h>

#include <stdlib.h>


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <elf-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    Elf64_Ehdr ehdr;
    fread(&ehdr, 1, sizeof(ehdr), f);

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        return 1;
    }

    printf("Entry point: 0x%lx\n", ehdr.e_entry);

    fclose(f);
    return 0;
}