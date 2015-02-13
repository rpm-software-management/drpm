/*
    Authors:
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2015 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <drpm.h>

#define DRPM_TEST_ERR_ARG 9
#define DRPM_TEST_TAGS_NUM 9
#define DRPM_TEST_TAGS_MAXLEN 17
#define DRPM_TEST_ERRS_MAXLEN 31

int main(int argc, char **argv)
{
   drpm *delta;
   int error;
   unsigned drpm_uint;
   char *drpm_string;

   int tags[DRPM_TEST_TAGS_NUM] = {
      DRPM_TAG_FILENAME,
      DRPM_TAG_VERSION,
      DRPM_TAG_TYPE,
      DRPM_TAG_COMP,
      DRPM_TAG_SEQUENCE,
      DRPM_TAG_SRCNEVR,
      DRPM_TAG_TGTNEVR,
      DRPM_TAG_TGTSIZE,
      DRPM_TAG_TGTMD5
   };
   char tag_names[DRPM_TEST_TAGS_NUM][DRPM_TEST_TAGS_MAXLEN] = {
      "file name",
      "version",
      "delta type",
      "compression type",
      "sequence",
      "source nevr",
      "target nevr",
      "target size",
      "target md5"
   };
   char errors[][DRPM_TEST_ERRS_MAXLEN] = {
      "no error",
      "memory allocation error",
      "bad arguments",
      "I/O error",
      "wrong file format",
      "misconfigured external library",
      "unspecified/unknown error"
   };

   if (argc != 2) {
      fprintf(stderr, "usage: drpm_test DELTARPM\n");
      return DRPM_TEST_ERR_ARG;
   } 

   /* int drpm_read(drpm **delta, const char *filename) */
   if ((error = drpm_read(&delta, argv[1])) != DRPM_ERR_OK) {
      fprintf(stderr, "error reading deltarpm file: %s\n", errors[error]);
      return error;
   }

   for (int i = 0; i < DRPM_TEST_TAGS_NUM; i++) {
      switch(tags[i]) {
         case DRPM_TAG_VERSION:
         case DRPM_TAG_TYPE:
         case DRPM_TAG_COMP:
         case DRPM_TAG_TGTSIZE:
            /* int drpm_get_uint(drpm *delta, int tag, unsigned *target) */
            if ((error = drpm_get_uint(delta, tags[i], &drpm_uint))
                != DRPM_ERR_OK) {
               fprintf(stderr, "%serror fetching %s: %s\n", 
                       i ? "\n" : "", tag_names[i], errors[error]);
               return error;
            }
            printf("%s: ", tag_names[i]);
            if (tags[i] == DRPM_TAG_TYPE) {
               printf("%s\n", drpm_uint == DRPM_TYPE_STANDARD
                      ? "standard" : "rpm-only");
            } else if (tags[i] == DRPM_TAG_COMP) {
               switch(drpm_uint) {
                  case DRPM_COMP_NONE:
                     printf("none\n");
                     break;
                  case DRPM_COMP_GZIP:
                     printf("gzip\n");
                     break;
                  case DRPM_COMP_BZIP2:
                     printf("bzip2\n");
                     break;
                  case DRPM_COMP_LZMA:
                     printf("lzma\n");
                     break;
                  case DRPM_COMP_XZ:
                     printf("xz\n");
                     break;
               }
            } else {
               printf("%u\n", drpm_uint);
            }
            break;
         case DRPM_TAG_FILENAME:
         case DRPM_TAG_SEQUENCE:
         case DRPM_TAG_SRCNEVR:
         case DRPM_TAG_TGTNEVR:
         case DRPM_TAG_TGTMD5:
            /* int drpm_get_string(drpm *delta, int tag, char **target) */
            if ((error = drpm_get_string(delta, tags[i], &drpm_string))
                != DRPM_ERR_OK) {
               fprintf(stderr, "%serror fetching %s: %s\n", 
                       i ? "\n" : "", tag_names[i], errors[error]);
               return error;
            }
            printf("%s: %s\n", tag_names[i], drpm_string);
            free(drpm_string);
            break;
      }
   }

   /* int drpm_destroy(drpm **delta) */
   if ((error = drpm_destroy(&delta)) != DRPM_ERR_OK) {
      fprintf(stderr, "\nerror destroying drpm: %s\n", errors[error]);
   }

   return error;
}
