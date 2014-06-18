#ifndef _DRPM_PRIVATE_H_
#define _DRPM_PRIVATE_H_

#include <stdint.h>
#include <stdlib.h>

#define MD5_BYTES 16

struct drpm {
    char *filename;
    uint32_t version;
    uint32_t type;
    uint32_t comp;
    char *sequence;
    char *src_nevr;
    char *tgt_nevr;
    uint32_t tgt_size;
    char tgt_md5[MD5_BYTES * 2 + 1];
};

//drpm_compstrm.c
struct compstrm;
int compstrm_destroy(struct compstrm **);
int compstrm_init(struct compstrm **, int, uint32_t *);
int compstrm_read(struct compstrm *, size_t, char *);
int compstrm_read_be32(struct compstrm *, uint32_t *);

//drpm_read.c
int read_be32(int, uint32_t *);
int readdelta_rest(int, struct drpm *);
int readdelta_rpmonly(int, struct drpm *);
int readdelta_standard(int, struct drpm *);

//drpm_utils.c
void dump_hex(char *, char *, size_t);
uint32_t parse_be32(char *);

#endif
