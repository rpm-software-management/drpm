#ifndef _DRPM_H_
#define _DRPM_H_

#include <errno.h>
#include <stdint.h>

//errors
#define EOK 0

//delta types
#define DRPM_TYPE_STANDARD 0
#define DRPM_TYPE_RPMONLY 1

//compression types
#define DRPM_COMP_NONE 0
#define DRPM_COMP_GZIP 1
#define DRPM_COMP_BZIP2 2
#define DRPM_COMP_LZMA 3
#define DRPM_COMP_XZ 4

//info tags
#define DRPM_FILENAME 0
#define DRPM_DELTA_VERSION 1
#define DRPM_DELTA_TYPE 2
#define DRPM_COMPRESSION 3
#define DRPM_SEQUENCE 4
#define DRPM_SOURCE_NEVR 5
#define DRPM_TARGET_NEVR 6
#define DRPM_TARGET_SIZE 7
#define DRPM_TARGET_MD5 8

struct drpm;

int drpm_destroy(struct drpm **);
int drpm_get_uint(struct drpm *, int, uint32_t *);
int drpm_get_string(struct drpm *, int, char **);
int drpm_read(char *, struct drpm **);

#endif
