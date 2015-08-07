/*
    Authors:
        Pavel Tobias <ptobias@redhat.com>
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2014 Red Hat

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

/**
 * @file drpm.h
 * @author Pavel Tobias <ptobias@redhat.com>
 * @author Matej Chalk <mchalk@redhat.com>
 * @date 2014-2015
 * @copyright Copyright &copy; 2014 Red Hat, Inc.
 * This project is released under the GNU Lesser Public License.
 */

#ifndef _DRPM_H_
#define _DRPM_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/** @name Errors */
/**@{*/
#define DRPM_ERR_OK 0       /**< no error */
#define DRPM_ERR_MEMORY 1   /**< memory allocation error */
#define DRPM_ERR_ARGS 2     /**< bad arguments */
#define DRPM_ERR_IO 3       /**< I/O error */
#define DRPM_ERR_FORMAT 4   /**< wrong file format */
#define DRPM_ERR_CONFIG 5   /**< misconfigured external library */
#define DRPM_ERR_OTHER 6    /**< unspecified/unknown error */
/**@}*/

/** @name Delta Types */
/**@{*/
#define DRPM_TYPE_STANDARD 0    /**< standard deltarpm */
#define DRPM_TYPE_RPMONLY 1     /**< rpm-only deltarpm */
/**@}*/

/** @name Compression Types */
/**@{*/
#define DRPM_COMP_NONE 0    /**< no compression */
#define DRPM_COMP_GZIP 1    /**< gzip */
#define DRPM_COMP_BZIP2 2   /**< bzip2 */
#define DRPM_COMP_LZMA 3    /**< lzma */
#define DRPM_COMP_XZ 4      /**< xz */
#define DRPM_COMP_LZIP 5    /**< lzip */
/**@}*/

/** @name Info Tags */
/**@{*/
#define DRPM_TAG_FILENAME 0         /**< file name */
#define DRPM_TAG_VERSION 1          /**< version */
#define DRPM_TAG_TYPE 2             /**< delta type */
#define DRPM_TAG_COMP 3             /**< compression type */
#define DRPM_TAG_SEQUENCE 4         /**< sequence */
#define DRPM_TAG_SRCNEVR 5          /**< source NEVR (name-epoch:version-release) */
#define DRPM_TAG_TGTNEVR 6          /**< target NEVR (name-epoch:version-release) */
#define DRPM_TAG_TGTSIZE 7          /**< target size */
#define DRPM_TAG_TGTMD5 8           /**< target MD5 */
#define DRPM_TAG_TGTCOMP 9          /**< target compression type */
#define DRPM_TAG_TGTCOMPPARAM 10    /**< target compression parameter block */
#define DRPM_TAG_TGTHEADERLEN 11    /**< target header length */
#define DRPM_TAG_ADJELEMS 12        /**< adjust elements */
#define DRPM_TAG_TGTLEAD 13         /**< lead/signatures of the new rpm */
#define DRPM_TAG_PAYLOADFMTOFF 14   /**< payload format offset */
#define DRPM_TAG_INTCOPIES 15       /**< copies from internal data (number of external copies to do before internal copy + length of internal copy) */
#define DRPM_TAG_EXTCOPIES 16       /**< copies from external data (offset adjustment of external copy + length of external copy) */
#define DRPM_TAG_EXTDATALEN 17      /**< length of external data */
#define DRPM_TAG_INTDATALEN 18      /**< length of internal data */
/**@}*/

/** @name Delta Creation Flags */
/**@{*/
#define DRPM_FLAG_NONE 0                /**< no additional flags */
#define DRPM_FLAG_RPMONLY (1<<0)        /**< "rpm-only" deltarpm */
#define DRPM_FLAG_VERSION_1 (1<<1)      /**< V1 deltarpm */
#define DRPM_FLAG_VERSION_2 (1<<2)      /**< V2 deltarpm */
#define DRPM_FLAG_VERSION_3 (1<<3)      /**< V3 deltarpm */
#define DRPM_FLAG_COMP_NONE (1<<4)      /**< uncompressed deltarpm */
#define DRPM_FLAG_COMP_GZIP (1<<5)      /**< gzip compressed deltarpm */
#define DRPM_FLAG_COMP_BZIP2 (1<<6)     /**< bzip2 compressed deltarpm */
#define DRPM_FLAG_COMP_LZMA (1<<7)      /**< lzma compressed deltarpm */
#define DRPM_FLAG_COMP_XZ (1<<8)        /**< xz compressed deltarpm */
#define DRPM_FLAG_COMP_LEVEL_1 (1<<9)   /**< compression level 1 */
#define DRPM_FLAG_COMP_LEVEL_2 (1<<10)  /**< compression level 2 */
#define DRPM_FLAG_COMP_LEVEL_3 (1<<11)  /**< compression level 3 */
#define DRPM_FLAG_COMP_LEVEL_4 (1<<12)  /**< compression level 4 */
#define DRPM_FLAG_COMP_LEVEL_5 (1<<13)  /**< compression level 5 */
#define DRPM_FLAG_COMP_LEVEL_6 (1<<14)  /**< compression level 6 */
#define DRPM_FLAG_COMP_LEVEL_7 (1<<15)  /**< compression level 7 */
#define DRPM_FLAG_COMP_LEVEL_8 (1<<16)  /**< compression level 8 */
#define DRPM_FLAG_COMP_LEVEL_9 (1<<17)  /**< compression level 9 */
/**@}*/

typedef struct drpm drpm; /**< deltarpm package info */

/**
 * @brief Creates a deltarpm from two rpms.
 *
 * Does the same thing as the
 * [makedeltarpm(8)](http://linux.die.net/man/8/makedeltarpm)
 * command-line utility.
 *
 * Examples of function calls:
 * @code
 * // makedeltarpm foo.rpm goo.rpm fg.drpm
 * drpm_make("foo.rpm", "goo.rpm", "fg.drpm", NULL, DRPM_FLAG_NONE)
 * @endcode
 * @code
 * // makedeltarpm -r -s seqfile.txt foo.rpm goo.rpm fg.drpm
 * drpm_make("foo.rpm", "goo.rpm", "fg.drpm", "seqfile.txt", DRPM_FLAG_RPMONLY)
 * @endcode
 * @code
 * // makedeltarpm -V 2 -z uncompressed foo.rpm goo.rpm fg.drpm
 * drpm_make("foo.rpm", "goo.rpm", "fg.drpm", NULL, DRPM_FLAG_VERSION_3 | DRPM_FLAG_COMP_NONE)
 * @endcode
 * @code
 * // makedeltarpm -z xz.6 foo.rpm goo.rpm fg.drpm
 * drpm_make("foo.rpm", "goo.rpm", "fg.drpm", NULL, DRPM_FLAG_COMP_XZ | DRPM_FLAG_COMP_LEVEL_6)
 * @endcode
 * @code
 * // makedeltarpm -u -z bzip2 foo.rpm foo.drpm
 * drpm_make("foo.rpm", NULL, "foo.drpm", NULL, DRPM_FLAG_COMP_BZIP2)
 * @endcode
 * @param [in]  old_rpm     Name of old RPM file.
 * @param [in]  new_rpm     Name of new RPM file.
 * @param [in]  deltarpm    Name of DeltaRPM file to be created.
 * @param [in]  seqfile     Name of file to which to write out @p deltarpm sequence.
 * @param [in]  flags       Bitwise OR of macros specifying options.
 * @return error number
 * @note Sequence is only written to file if @p seqfile is not @c NULL.
 * @note If either @p old_rpm or @p new_rpm is @c NULL, an "identity"
 * deltarpm is created.
 * @see DRPM_FLAG_NONE
 * @see DRPM_FLAG_RPMONLY
 * @see DRPM_FLAG_VERSION_1, DRPM_FLAG_VERSION_2, DRPM_FLAG_VERSION_3
 * @see DRPM_FLAG_COMP_NONE, DRPM_FLAG_COMP_GZIP, DRPM_FLAG_COMP_BZIP2,
 * DRPM_FLAG_COMP_LZMA, DRPM_FLAG_COMP_XZ
 */
int drpm_make(const char *old_rpm, const char *new_rpm, const char *delta_rpm, const char *seqfile, int flags);

/**
 * @brief Reads information from deltarpm package @p filename into @p *delta.
 * 
 * Example of usage:
 * @code
 * drpm *delta = NULL;
 *
 * int error = drpm_read(&delta, "foo.drpm");
 *
 * if (error != DRPM_ERR_OK) {
 *    fprintf(stderr, "drpm error: %s\n", drpm_strerror(error));
 *    return;
 * }
 * @endcode
 * @param [out] delta       deltarpm to be filled with info
 * @param [in]  filename    name of deltarpm file whose data is to be read
 * @return error number
 * @note Memory allocated by calling drpm_read() should later be freed
 * by calling drpm_destroy().
 */
int drpm_read(drpm **delta, const char *filename);

/**
 * @brief Fetches information representable as an unsigned integer.
 * 
 * Fetches information identified by @p tag from @p delta and copies it 
 * to address pointed to by @p target.
 * 
 * Example of usage:
 * @code
 * unsigned type;
 *
 * int error = drpm_get_uint(delta, DRPM_TAG_TYPE, &type);
 *
 * if (error != DRPM_ERR_OK) {
 *    fprintf(stderr, "drpm error: %s\n", drpm_strerror(error));
 *    return;
 * }
 *
 * printf("This is a %s deltarpm\n", (type == DRPM_TYPE_STANDARD) ? "standard" : "rpm-only");
 * @endcode
 * @param [in]  delta   deltarpm containing required info
 * @param [in]  tag     identifies which info is required
 * @param [out] target  tagged info will be copied here
 * @return error number
 * @warning @p delta should have been previously initialized with
 * drpm_read(), otherwise behaviour is undefined.
 * @see DRPM_TAG_VERSION
 * @see DRPM_TAG_TYPE
 * @see DRPM_TAG_COMP
 * @see DRPM_TAG_TGTCOMP
 */
int drpm_get_uint(drpm *delta, int tag, unsigned *target);

/**
 * @brief Fetches information representable as an unsigned long integer.
 *
 * Fetches information identified by @p tag from @p delta and copies it
 * to address pointed to by @p target.
 *
 * Example of usage:
 * @code
 * unsigned long tgt_size;
 *
 * int error = drpm_get_ulong(delta, DRPM_TAG_TGTSIZE, &tgt_size);
 *
 * if (error != DRPM_ERR_OK) {
 *    fprintf(stderr, "drpm error: %s\n", drpm_strerror(error));
 *    return;
 * }
 *
 * printf("Size of new RPM: %lu\n", tgt_size);
 * @endcode
 * @param [in]  delta   deltarpm containing required info
 * @param [in]  tag     identifies which info is required
 * @param [out] target  tagged info will be copied here
 * @return error number
 * @warning @p delta should have been previously initialized with
 * drpm_read(), otherwise behaviour is undefined.
 * @see DRPM_TAG_VERSION
 * @see DRPM_TAG_TYPE
 * @see DRPM_TAG_COMP
 * @see DRPM_TAG_TGTSIZE
 * @see DRPM_TAG_TGTCOMP
 * @see DRPM_TAG_TGTHEADERLEN
 * @see DRPM_TAG_PAYLOADFMTOFF
 */
int drpm_get_ulong(drpm *delta, int tag, unsigned long *target);

/**
 * @brief Fetches information representable as an unsigned long long integer.
 *
 * Fetches information identified by @p tag from @p delta and copies it
 * to address pointed to by @p target.
 *
 * Example of usage:
 * @code
 * unsigned long long int_data_len;
 *
 * int error = drpm_get_ullong(delta, DRPM_TAG_INTDATALEN, &int_data_len);
 *
 * if (error != DRPM_ERR_OK) {
 *    fprintf(stderr, "drpm error: %s\n", drpm_strerror(error));
 *    return;
 * }
 *
 * printf("Length of internal data: %llu\n", int_data_len);
 * @endcode
 * @param [in]  delta   deltarpm containing required info
 * @param [in]  tag     identifies which info is required
 * @param [out] target  tagged info will be copied here
 * @return error number
 * @warning @p delta should have been previously initialized with
 * drpm_read(), otherwise behaviour is undefined.
 * @see DRPM_TAG_VERSION
 * @see DRPM_TAG_TYPE
 * @see DRPM_TAG_COMP
 * @see DRPM_TAG_TGTSIZE
 * @see DRPM_TAG_TGTCOMP
 * @see DRPM_TAG_TGTHEADERLEN
 * @see DRPM_TAG_PAYLOADFMTOFF
 * @see DRPM_TAG_EXTDATALEN
 * @see DRPM_TAG_INTDATALEN
 */
int drpm_get_ullong(drpm *delta, int tag, unsigned long long *target);

/**
 * @brief Fetches information representable as a string.
 * 
 * Fetches string-type information identified by @p tag from @p delta, 
 * copies it to space previously allocated by the function itself and 
 * saves the address to @p *target.
 *
 * Example of usage:
 * @code
 * char *tgt_nevr;
 *
 * int error = drpm_get_string(delta, DRPM_TAG_TGTNEVR, &tgt_nevr);
 *
 * if (error != DRPM_ERR_OK) {
 *    fprintf(stderr, "drpm error: %s\n", drpm_strerror(error));
 *    return;
 * }
 *
 * printf("Target NEVR: %s\n", tgt_nevr);
 *
 * free(tgt_nevr);
 * @endcode
 * @param [in]  delta   deltarpm containing required info
 * @param [in]  tag     identifies which info is required
 * @param [out] target  tagged info will be copied here
 * @return error number
 * @note @p *target should be freed manually by the user when no longer needed.
 * @warning @p delta should have been previously initialized with
 * drpm_read(), otherwise behaviour is undefined.
 * @see DRPM_TAG_FILENAME
 * @see DRPM_TAG_SEQUENCE
 * @see DRPM_TAG_SRCNEVR
 * @see DRPM_TAG_TGTNEVR
 * @see DRPM_TAG_TGTMD5
 * @see DRPM_TAG_TGTCOMPPARAM
 * @see DRPM_TAG_TGTLEAD
 */
int drpm_get_string(drpm *delta, int tag, char **target);

/**
 * @brief Fetches information representable as an array of unsigned long integers.
 *
 * Fetches information identified by @p tag from @p delta,
 * copies it to space previously allocated by the function itself,
 * saves the address to @p *target and stores size in @p *size.
 *
 * Example of usage:
 * @code
 * unsigned long *ext_copies;
 * unsigned long ext_copies_size;
 *
 * int error = drpm_get_ulong_array(delta, DRPM_TAG_EXTCOPIES, &ext_copies, &ext_copies_size);
 *
 * if (error != DRPM_ERR_OK) {
 *    fprintf(stderr, "drpm error: %s\n", drpm_strerror(error));
 *    return;
 * }
 *
 * for (unsigned long i = 1; i < ext_copies_size; i += 2)
 *    printf("External copy: offset adjustment = %lu, length = %lu\n", ext_copies[i-1], ext_copies[i]);
 *
 * free(ext_copies);
 * @endcode
 * @param [in]  delta   deltarpm containing required info
 * @param [in]  tag     identifies which info is required
 * @param [out] target  tagged info will be copied here
 * @param [out] size    size of array will be copied here
 * @return error number
 * @note @p *target should be freed manually by the user when no longer needed.
 * @warning @p delta should have been previously initialized with
 * drpm_read(), otherwise behaviour is undefined.
 * @see DRPM_TAG_ADJELEMS
 * @see DRPM_TAG_INTCOPIES
 * @see DRPM_TAG_EXTCOPIES
 */
int drpm_get_ulong_array(drpm *delta, int tag, unsigned long **target, unsigned long *size);

/**
 * @brief Frees memory pointed to by @p *delta and sets @p *delta to @c NULL.
 * 
 * Example of usage:
 * @code
 * int error = drpm_destroy(&delta);
 *
 * if (error != DRPM_ERR_OK) {
 *    fprintf(stderr, "drpm error: %s\n", drpm_strerror(error));
 *    return;
 * }
 * @endcode
 * @param [out] delta   deltarpm that is to be freed
 * @return error number
 * @warning @p delta should have been previously initialized with
 * drpm_read(), otherwise behaviour is undefined.
 */
int drpm_destroy(drpm **delta);

/**
 * @brief Returns description of error code as a string.
 *
 * Works very similarly to
 * [strerror(3)](http://linux.die.net/man/3/strerror).
 * @param [in]  error   error code
 * @return error description (or @c NULL if error code invalid)
 */
const char *drpm_strerror(int error);

#endif
