/*
    Authors:
        Pavel Tobias <ptobias@redhat.com>
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2014 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file
 * @author Pavel Tobias <ptobias@redhat.com>
 * @author Matej Chalk <mchalk@redhat.com>
 * @date 2014-2016
 * @copyright Copyright &copy; 2014-2016 Red Hat, Inc.
 * This project is released under the GNU Lesser Public License.
 */

#ifndef _DRPM_H_
#define _DRPM_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/**
 * @defgroup drpmMake DRPM Make
 * Tools for creating a DeltaRPM file from two RPM files,
 * providing the same functionality as
 * [makedeltarpm(8)](http://linux.die.net/man/8/makedeltarpm).
 * @{
 * @defgroup drpmMakeOptions DRPM Make Options
 * Tools for customizing DeltaRPM creation.
 * @}
 *
 * @defgroup drpmApply DRPM Apply
 * Tools for applying a DeltaRPM file to re-create a new RPM file
 * (from an old RPM file or from filesystem data),
 * providing the same functionality as
 * [applydeltarpm(8)](http://linux.die.net/man/8/applydeltarpm).
 * @{
 * @defgroup drpmCheck DRPM Check
 * Tools for checking if the reconstruction is possible
 * (like <tt>applydeltarpm { -c | -C }</tt>).
 * @}
 *
 * @defgroup drpmRead DRPM Read
 * Tools for extracting information from DeltaRPM files.
 */

/**
 * @name Errors / Return values
 * @{
 */
#define DRPM_ERR_OK 0           /**< no error */
#define DRPM_ERR_MEMORY 1       /**< memory allocation error */
#define DRPM_ERR_ARGS 2         /**< bad arguments */
#define DRPM_ERR_IO 3           /**< I/O error */
#define DRPM_ERR_FORMAT 4       /**< wrong file format */
#define DRPM_ERR_CONFIG 5       /**< misconfigured external library */
#define DRPM_ERR_OTHER 6        /**< unspecified/unknown error */
#define DRPM_ERR_OVERFLOW 7     /**< file too large */
#define DRPM_ERR_PROG 8         /**< internal programming error */
#define DRPM_ERR_MISMATCH 9     /**< file changed */
#define DRPM_ERR_NOINSTALL 10   /**< old RPM not installed */
/** @} */

/**
 * @name Delta Types
 * @{
 */
#define DRPM_TYPE_STANDARD 0    /**< standard deltarpm */
#define DRPM_TYPE_RPMONLY 1     /**< rpm-only deltarpm */
/** @} */

/**
 * @name Compression Types
 * @{
 */
#define DRPM_COMP_NONE 0    /**< no compression */
#define DRPM_COMP_GZIP 1    /**< gzip */
#define DRPM_COMP_BZIP2 2   /**< bzip2 */
#define DRPM_COMP_LZMA 3    /**< lzma */
#define DRPM_COMP_XZ 4      /**< xz */
#ifdef HAVE_LZLIB_DEVEL
/**
 * @brief lzip
 *
 * The original deltarpm implementation does not support lzip.
 * DeltaRPM packages compressed with lzip will work within this API, but
 * will not be backwards-compatible.
 *
 * This compression algorithm is supported because newer versions
 * of RPM packages may be compressed with lzip.
 */
#endif
#define DRPM_COMP_LZIP 5    /**< lzip */
#define DRPM_COMP_ZSTD 6    /**< zstd */
/** @} */

/**
 * @name Info Tags
 * @{
 */
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
#define DRPM_TAG_ADJELEMS 12        /**< offset adjustment elements */
#define DRPM_TAG_TGTLEAD 13         /**< lead/signatures of the new rpm */
#define DRPM_TAG_PAYLOADFMTOFF 14   /**< payload format offset */
#define DRPM_TAG_INTCOPIES 15       /**< copies from internal data (number of external copies to do before internal copy & length of internal copy) */
#define DRPM_TAG_EXTCOPIES 16       /**< copies from external data (offset adjustment of external copy & length of external copy) */
#define DRPM_TAG_EXTDATALEN 17      /**< length of external data */
#define DRPM_TAG_INTDATALEN 18      /**< length of internal data */
/** @} */

/**
 * @name Compression Levels
 * @{
 */
#define DRPM_COMP_LEVEL_DEFAULT 0   /**< default compression level for given compression type */
/** @} */

/**
 * @name Check Modes
 * @{
 */
#define DRPM_CHECK_NONE 0           /**< no file checking */
#define DRPM_CHECK_FULL 1           /**< full (i.e.\ slow) on-disk checking */
#define DRPM_CHECK_FILESIZES 2      /**< only checking if filesizes have changed */
/** @} */

/**
 * @brief DeltaRPM package info
 * @ingroup drpmRead
 */
typedef struct drpm drpm;

/**
 * @brief Options for drpm_make()
 * @ingroup drpmMakeOptions
 */
typedef struct drpm_make_options drpm_make_options;

/**
 * @ingroup drpmApply
 * @brief Applies a DeltaRPM to an old RPM or on-disk data to re-create a new RPM.
 * @param [in]  oldrpm      Name of old RPM file (if @c NULL, filesystem data is used).
 * @param [in]  deltarpm    Name of DeltaRPM file.
 * @param [in]  newrpm      Name of new RPM file to be (re-)created.
 * @return Error code.
 */
int drpm_apply(const char *oldrpm, const char *deltarpm, const char *newrpm);

/**
 * @ingroup drpmCheck
 * @brief Checks if the reconstruction is possible based on DeltaRPM file.
 * @param [in]  deltarpm    Name of DeltaRPM file.
 * @param [in]  checkmode   Full check or filesize changes only.
 * @return Error code.
 * @see DRPM_CHECK_FULL, DRPM_CHECK_FILESIZES
 */
int drpm_check(const char *deltarpm, int checkmode);

/**
 * @ingroup drpmCheck
 * @brief Checks if the reconstruction is possible based on sequence ID.
 * @param [in]  oldrpm      Name of old RPM file (if @c NULL, filesystem data is used).
 * @param [in]  sequence    Sequence ID of the DeltaRPM.
 * @param [in]  checkmode   Full check or filesize changes only.
 * @return Error code.
 * @see DRPM_CHECK_FULL, DRPM_CHECK_FILESIZES
 */
int drpm_check_sequence(const char *oldrpm, const char *sequence, int checkmode);

/**
 * @ingroup drpmMake
 * @brief Creates a DeltaRPM from two RPMs.
 * The DeltaRPM can later be used to recreate the new RPM from either
 * filesystem data or the old RPM.
 *
 * Does the same thing as the
 * [makedeltarpm(8)](http://linux.die.net/man/8/makedeltarpm)
 * command-line utility.
 *
 * Examples of function calls (without error handling):
 * @code
 * // makedeltarpm foo.rpm goo.rpm fg.drpm
 * drpm_make("foo.rpm", "goo.rpm", "fg.drpm", NULL);
 * @endcode
 * @code
 * // makedeltarpm -r -z xz.6 -s seqfile.txt foo.rpm goo.rpm fg.drpm
 *
 * drpm_make_options *opts;
 *
 * drpm_make_options_init(&opts);
 * drpm_make_options_set_type(opts, DRPM_TYPE_RPMONLY);
 * drpm_make_options_set_seqfile(opts, "seqfile.txt");
 * drpm_make_options_set_delta_comp(opts, DRPM_COMP_XZ, 6);
 *
 * drpm_make("foo.rpm", "goo.rpm", "fg.drpm", &opts);
 *
 * drpm_make_options_destroy(&opts);
 * @endcode
 * @code
 * // makedeltarpm -V 2 -z gzip,off -p foo-print.rpml foo-patch.rpml foo.rpm goo.rpm fg.drpm
 *
 * drpm_make_options *opts;
 *
 * drpm_make_options_init(&opts);
 * drpm_make_options_set_version(opts, 2);
 * drpm_make_options_set_delta_comp(opts, DRPM_COMP_GZIP, DRPM_COMP_LEVEL_DEFAULT);
 * drpm_make_options_forbid_addblk(opts);
 * drpm_make_options_add_patches(opts, "foo-print.rpml", "foo-patch.rpml");
 *
 * drpm_make("foo.rpm", "goo.rpm", "fg.drpm", &opts);
 *
 * drpm_make_options_destroy(&opts);
 * @endcode
 * @code
 * // makedeltarpm -z uncompressed,bzip2.9 foo.rpm goo.rpm fg.drpm
 *
 * drpm_make_options *opts;
 *
 * drpm_make_options_init(&opts);
 * drpm_make_options_set_delta_comp(opts, DRPM_COMP_NONE, 0);
 * drpm_make_options_set_addblk_comp(opts, DRPM_COMP_BZIP2, 9);
 *
 * drpm_make("foo.rpm", "goo.rpm", "fg.drpm", &opts);
 *
 * drpm_make_options_destroy(&opts);
 * @endcode
 * @code
 * // makedeltarpm -u foo.rpm foo.drpm
 * drpm_make("foo.rpm", NULL, "foo.drpm", NULL);
 * @endcode
 * @param [in]  oldrpm      Name of old RPM file.
 * @param [in]  newrpm      Name of new RPM file.
 * @param [in]  deltarpm    Name of DeltaRPM file to be created.
 * @param [in]  opts        Options (if @c NULL, defaults used).
 * @return Error code.
 * @note If either @p old_rpm or @p new_rpm is @c NULL, an "identity"
 * deltarpm is created (may be useful to just replace the signature
 * of an RPM or to reconstruct an RPM from the filesystem).
 * @warning If not @c NULL, @p opts should have been initialized with
 * drpm_make_options_init(), otherwise behaviour is undefined.
 */
int drpm_make(const char *oldrpm, const char *newrpm, const char *deltarpm, const drpm_make_options *opts);

/**
 * @addtogroup drpmMakeOptions
 * @{
 */

/**
 * @brief Initializes ::drpm_make_options with default options.
 * Passing @p *opts to drpm_make() immediately after would have the same
 * effect as passing @c NULL instead.
 * @param [out] opts    Address of options structure pointer.
 * @return Error code.
 * @see drpm_make()
 */
int drpm_make_options_init(drpm_make_options **opts);

/**
 * @brief Frees ::drpm_make_options.
 * @param [out] opts    Address of options structure pointer.
 * @return Error code.
 * @see drpm_make()
 */
int drpm_make_options_destroy(drpm_make_options **opts);

/**
 * @brief Resets options to default values.
 * Passing @p opts to drpm_make() immediately after would have the same
 * effect as passing @c NULL instead.
 * @param [out] opts    Structure specifying options for drpm_make().
 * @return Error code.
 * @see drpm_make()
 */
int drpm_make_options_defaults(drpm_make_options *opts);

/**
 * @brief Copies ::drpm_make_options.
 * Copies data from @p src to @p dst.
 * @param [out] dst Destination options.
 * @param [in]  src Source options.
 * @return Error code.
 * @warning @p dst should have also been initialized with
 * drpm_make_options_init() previously, otherwise behaviour is undefined.
 * @see drpm_make()
 */
int drpm_make_options_copy(drpm_make_options *dst, const drpm_make_options *src);

/**
 * @brief Sets DeltaRPM type.
 * There are two types of DeltaRPMs: standard and "rpm-only".
 * The latter was introduced in version 3.
 * It does not work with filesystem data but is smaller and faster to
 * combine.
 * @param [out] opts    Structure specifying options for drpm_make().
 * @param [in]  type    Type of deltarpm.
 * @return Error code.
 * @see drpm_make()
 * @see DRPM_TYPE_STANDARD, DRPM_TYPE_RPMONLY
 */
int drpm_make_options_set_type(drpm_make_options *opts, unsigned short type);

/**
 * @brief Sets DeltaRPM version.
 * The default DeltaRPM format is V3, but an older version may also be
 * specified.
 * @param [out] opts    Structure specifying options for drpm_make().
 * @param [in]  version Version (1-3).
 * @return Error code.
 * @see drpm_make()
 */
int drpm_make_options_set_version(drpm_make_options *opts, unsigned short version);

/**
 * @brief Sets DeltaRPM compression type and level.
 * By default, the compression method is the same as used in the new RPM.
 * @param [out] opts    Structure specifying options for drpm_make().
 * @param [in]  comp    Compression type.
 * @param [in]  level   Compression level (1-9 or default).
 * @return Error code.
 * @see drpm_make()
 * @see DRPM_COMP_NONE, DRPM_COMP_GZIP, DRPM_COMP_BZIP2,
 * DRPM_COMP_LZMA, DRPM_COMP_XZ
 * @see DRPM_COMP_LEVEL_DEFAULT
 */
int drpm_make_options_set_delta_comp(drpm_make_options *opts, unsigned short comp, unsigned short level);

/**
 * @brief DeltaRPM compression method is the same as used in the new RPM.
 * May be used to reset DeltaRPM compression option after previously
 * calling drpm_make_options_delta_comp().
 * @param [out] opts    Structure specifying options for drpm_make().
 * @return Error code.
 * @see drpm_make()
 */
int drpm_make_options_get_delta_comp_from_rpm(drpm_make_options *opts);

/**
 * @brief Forbids add block creation.
 * An "add block" is a highly compressible block used to store
 * bytewise subtractions of segments where less than half the bytes
 * have changed.
 * It is used in re-creating the new RPM with drpm_apply(), unless this
 * functions is called to tell drpm_make() not to create an add block.
 * @param [out] opts    Structure specifying options for drpm_make().
 * @return Error code.
 * @see drpm_make()
 */
int drpm_make_options_forbid_addblk(drpm_make_options *opts);

/**
 * @brief Sets add block compression type and level.
 * The default add block compression type is bzip2, which gives the best
 * results.
 * @param [out] opts    Structure specifying options for drpm_make().
 * @param [in]  comp    Compression type.
 * @param [in]  level   Compression level (1-9 or default).
 * @return Error code.
 * @see drpm_make()
 * @see DRPM_COMP_NONE, DRPM_COMP_GZIP, DRPM_COMP_BZIP2,
 * DRPM_COMP_LZMA, DRPM_COMP_XZ
 * @see DRPM_COMP_LEVEL_DEFAULT
 */
int drpm_make_options_set_addblk_comp(drpm_make_options *opts, unsigned short comp, unsigned short level);

/**
 * @brief Specifies file to which to write DeltaRPM sequence ID.
 * If a valid file name is given, drpm_make() will write out
 * the sequence ID to the file @p seqfile.
 * @param [out] opts    Structure specifying options for drpm_make().
 * @param [in]  seqfile Name of file to which to write out sequence.
 * @return Error code.
 * @note If @p seqfile is @c NULL, sequence ID shall not be written.
 * @see drpm_make()
 */
int drpm_make_options_set_seqfile(drpm_make_options *opts, const char *seqfile);

/**
 * @brief Requests incorporation of RPM patch files for the old RPM.
 * This option enables the usage of patch RPMs, telling drpm_make() to
 * exclude all files that were not included in the patch RPM but are not
 * bytewise identical to the ones in the old RPM.
 * @param [out] opts        Structure specifying options for drpm_make().
 * @param [in]  oldrpmprint The rpm-print of the old RPM.
 * @param [in]  oldpatchrpm The created patch RPM.
 * @return Error code.
 * @see drpm_make()
 */
int drpm_make_options_add_patches(drpm_make_options *opts, const char *oldrpmprint, const char *oldpatchrpm);

/**
 * @brief Limits memory usage.
 * As drpm_make() normally needs about three to four times the size of
 * the rpm's uncompressed payload, this option may be used to enable
 * a sliding block algorithm that needs @p mbytes megabytes of memory.
 * This trades memory usage with the size of the created DeltaRPM.
 * @param [out] opts    Structure specifying options for drpm_make().
 * @param [in]  mbytes  Permitted memory usage in megabytes.
 * @return Error code.
 * @see drpm_make()
 */
//int drpm_make_options_set_memlimit(drpm_make_options *opts, unsigned mbytes);

/** @} */

/**
 * @addtogroup drpmRead
 * @{
 */

/**
 * @brief Reads information from a DeltaRPM.
 * Reads information from DeltaRPM package @p filename into @p *delta.
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
 * @param [out] delta       DeltaRPM to be filled with info.
 * @param [in]  filename    Name of DeltaRPM file whose data is to be read.
 * @return Error code.
 * @note Memory allocated by calling drpm_read() should later be freed
 * by calling drpm_destroy().
 */
int drpm_read(drpm **delta, const char *filename);

/**
 * @brief Fetches information representable as an unsigned integer.
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
 * @param [in]  delta   DeltaRPM containing required info.
 * @param [in]  tag     Identifies which info is required.
 * @param [out] target  Tagged info will be copied here.
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
 * @param [in]  delta   Deltarpm containing required info.
 * @param [in]  tag     Identifies which info is required.
 * @param [out] target  Tagged info will be copied here.
 * @return Error code.
 * @warning @p delta should have been previously initialized with
 * drpm_read(), otherwise behaviour is undefined.
 * @see DRPM_TAG_TGTSIZE
 * @see DRPM_TAG_TGTHEADERLEN
 * @see DRPM_TAG_PAYLOADFMTOFF
 */
int drpm_get_ulong(drpm *delta, int tag, unsigned long *target);

/**
 * @brief Fetches information representable as an unsigned long long integer.
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
 * @param [in]  delta   Deltarpm containing required info.
 * @param [in]  tag     Identifies which info is required.
 * @param [out] target  Tagged info will be copied here.
 * @return Error code.
 * @warning @p delta should have been previously initialized with
 * drpm_read(), otherwise behaviour is undefined.
 * @see DRPM_TAG_EXTDATALEN
 * @see DRPM_TAG_INTDATALEN
 */
int drpm_get_ullong(drpm *delta, int tag, unsigned long long *target);

/**
 * @brief Fetches information representable as a string.
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
 * @param [in]  delta   Deltarpm containing required info.
 * @param [in]  tag     Identifies which info is required.
 * @param [out] target  Tagged info will be copied here.
 * @return Error code.
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
 * @param [in]  delta   Deltarpm containing required info.
 * @param [in]  tag     Identifies which info is required.
 * @param [out] target  Tagged info will be copied here.
 * @param [out] size    Size of array will be copied here.
 * @return Error code.
 * @note @p *target should be freed manually by the user when no longer needed.
 * @warning @p delta should have been previously initialized with
 * drpm_read(), otherwise behaviour is undefined.
 * @see DRPM_TAG_ADJELEMS
 * @see DRPM_TAG_INTCOPIES
 * @see DRPM_TAG_EXTCOPIES
 */
int drpm_get_ulong_array(drpm *delta, int tag, unsigned long **target, unsigned long *size);

/**
 * @brief Frees memory allocated by drpm_read().
 * Frees memory pointed to by @p *delta and sets @p *delta to @c NULL.
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
 * @param [out] delta   Deltarpm that is to be freed.
 * @return Error code.
 * @warning @p delta should have been previously initialized with
 * drpm_read(), otherwise behaviour is undefined.
 */
int drpm_destroy(drpm **delta);

/** @} */

/**
 * @brief Returns description of error code as a string.
 * Works very similarly to
 * [strerror(3)](http://linux.die.net/man/3/strerror).
 * @param [in]  error   error code
 * @return error description
 */
const char *drpm_strerror(int error);

#endif
