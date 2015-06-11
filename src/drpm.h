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

/** @file drpm.h */

#ifndef _DRPM_H_
#define _DRPM_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/** @name errors */
/**@{*/
#define DRPM_ERR_OK 0         /**< no error */
#define DRPM_ERR_MEMORY 1     /**< memory allocation error */
#define DRPM_ERR_ARGS 2       /**< bad arguments */
#define DRPM_ERR_IO 3         /**< I/O error */
#define DRPM_ERR_FORMAT 4     /**< wrong file format */
#define DRPM_ERR_CONFIG 5     /**< misconfigured external library */
#define DRPM_ERR_OTHER 6      /**< unspecified/unknown error */
/**@}*/

/** @name delta types */
/**@{*/
#define DRPM_TYPE_STANDARD 0  /**< standard deltarpm */
#define DRPM_TYPE_RPMONLY 1   /**< rpm-only deltarpm */
/**@}*/

/** @name compression types */
/**@{*/
#define DRPM_COMP_NONE 0      /**< no compression */
#define DRPM_COMP_GZIP 1      /**< gzip */
#define DRPM_COMP_BZIP2 2     /**< bzip2 */
#define DRPM_COMP_LZMA 3      /**< lzma */
#define DRPM_COMP_XZ 4        /**< xz */
/**@}*/

/** @name info tags */
/**@{*/
#define DRPM_TAG_FILENAME 0   /**< file name */
#define DRPM_TAG_VERSION 1    /**< version */
#define DRPM_TAG_TYPE 2       /**< delta type */
#define DRPM_TAG_COMP 3       /**< compression type */
#define DRPM_TAG_SEQUENCE 4   /**< sequence */
#define DRPM_TAG_SRCNEVR 5    /**< source NEVR (name-epoch:version-release) */
#define DRPM_TAG_TGTNEVR 6    /**< target NEVR (name-epoch:version-release) */
#define DRPM_TAG_TGTSIZE 7    /**< target size */
#define DRPM_TAG_TGTMD5 8     /**< target MD5 */
/**@}*/

typedef struct drpm drpm; /**< abstract data type of deltarpm structure */

/**
 * @brief Reads information from a deltarpm package @p filename into @p *delta.
 * 
 * Example of usage:
 * @code
 * drpm *delta = NULL;
 * int error = drpm_read(&delta, argv[1]);
 * if (error != DRPM_ERR_OK)
 *    return error;
 * @endcode
 * @param [out] delta deltarpm to be filled with info
 * @param [in] filename name of deltarpm file whose data is to be read
 * @return error number
 * @note Memory allocated by calling drpm_read() should later be freed
 * by calling drpm_destroy().
 */
int drpm_read(drpm **delta, const char *filename);

/**
 * @brief Fetches information representable as an unsigned integer.
 * 
 * Fetches information identified by @p tag from @p delta and copies it 
 * to adress pointed to by @p target.
 * 
 * Example of usage:
 * @code
 * unsigned type;
 * int error = drpm_get_uint(delta, DRPM_TAG_TYPE, &type);
 * if (error != DRPM_ERR_OK)
 *    return error;
 * printf("This is a %s deltarpm\n", comp_type == DRPM_TYPE_STANDARD ? "standard" : "rpm-only");
 * @endcode
 * @param [in] delta deltarpm containing required info
 * @param [in] tag symbolic value identifying which info is required
 * @param [out] target tagged info will be copied here
 * @return error number
 * @warning Must be preceded by call to drpm_read().
 */
int drpm_get_uint(drpm *delta, int tag, unsigned *target);

/**
 * @brief Fetches information representable as a string.
 * 
 * Fetches string-type information identified by @p tag from @p delta, 
 * copies it to space previously allocated by the function itself and 
 * saves the adress to @p *target.
 * 
 * Example of usage:
 * @code
 * char *tgt_nevr;
 * int error = drpm_get_string(delta, DRPM_TAG_TGTNEVR, &tgt_nevr);
 * if (error != DRPM_ERR_OK)
 *    return error;
 * printf("Target NEVR: %s\n", tgt_nevr);
 * free(tgt_nevr);
 * @endcode
 * @param [in] delta deltarpm containing required info
 * @param [in] tag symbolic value identifying which info is required
 * @param [out] target tagged info will be copied here
 * @return error number
 * @note @p *target should be freed manually by the user when no longer needed.
 * @warning Must be preceded by call to drpm_read().
 */
int drpm_get_string(drpm *delta, int tag, char **target);

/**
 * @brief Frees memory pointed to by @p *delta and sets @p *delta to @c NULL.
 * 
 * Example of usage:
 * @code
 * int error = drpm_destroy(&delta);
 * if (error != DRPM_ERR_OK)
 *    return error;
 * @endcode
 * @param [out] delta deltarpm that is to be freed
 * @return error number
 * @warning Must be preceded by call to drpm_read().
 */
int drpm_destroy(drpm **delta);

#endif
