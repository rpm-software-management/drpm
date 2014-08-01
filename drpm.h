#ifndef _DRPM_H_
#define _DRPM_H_

//errors
#define DRPM_ERR_OK 0
#define DRPM_ERR_MEMORY 1
#define DRPM_ERR_ARGS 2
#define DRPM_ERR_IO 3
#define DRPM_ERR_FORMAT 4
#define DRPM_ERR_CONFIG 5
#define DRPM_ERR_OTHER 6

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
#define DRPM_TAG_FILENAME 0
#define DRPM_TAG_VERSION 1
#define DRPM_TAG_TYPE 2
#define DRPM_TAG_COMP 3
#define DRPM_TAG_SEQUENCE 4
#define DRPM_TAG_SRCNEVR 5
#define DRPM_TAG_TGTNEVR 6
#define DRPM_TAG_TGTSIZE 7
#define DRPM_TAG_TGTMD5 8

struct drpm;

int drpm_destroy(struct drpm **delta);
int drpm_get_uint(struct drpm *delta, int tag, unsigned *target);
int drpm_get_string(struct drpm *delta, int tag, char **target);
int drpm_read(struct drpm **delta, const char *filename);

#endif
