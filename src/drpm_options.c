/*
    Authors:
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include "drpm.h"
#include "drpm_private.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>

int drpm_make_options_init(struct drpm_make_options **opts)
{
    const struct drpm_make_options init = {0};

    if (opts == NULL)
        return DRPM_ERR_ARGS;

    if ((*opts = malloc(sizeof(struct drpm_make_options))) == NULL)
        return DRPM_ERR_MEMORY;

    **opts = init;

    drpm_make_options_defaults(*opts);

    return DRPM_ERR_OK;
}

int drpm_make_options_destroy(struct drpm_make_options **opts)
{
    if (opts == NULL)
        return DRPM_ERR_ARGS;

    free((*opts)->seqfile);
    free((*opts)->oldrpmprint);
    free((*opts)->oldpatchrpm);
    free(*opts);
    *opts = NULL;

    return DRPM_ERR_OK;
}

int drpm_make_options_defaults(struct drpm_make_options *opts)
{
    if (opts == NULL)
        return DRPM_ERR_ARGS;

    free(opts->seqfile);
    free(opts->oldrpmprint);
    free(opts->oldpatchrpm);

    opts->rpm_only = false;
    opts->version = 3;
    opts->comp_from_rpm = true;
    opts->comp = USHRT_MAX;
    opts->comp_level = DRPM_COMP_LEVEL_DEFAULT;
    opts->addblk = true;
    opts->addblk_comp = DRPM_COMP_BZIP2;
    opts->addblk_comp_level = DRPM_COMP_LEVEL_DEFAULT;
    opts->seqfile = NULL;
    opts->oldrpmprint = NULL;
    opts->oldpatchrpm = NULL;
    opts->mbytes = 0;

    return DRPM_ERR_OK;
}

int drpm_make_options_copy(struct drpm_make_options *opts_dst, const struct drpm_make_options *opts_src)
{
    if (opts_dst == NULL || opts_src == NULL)
        return DRPM_ERR_ARGS;

    opts_dst->rpm_only = opts_src->rpm_only;
    opts_dst->version = opts_src->version;
    opts_dst->comp_from_rpm = opts_src->comp_from_rpm;
    opts_dst->comp = opts_src->comp;
    opts_dst->comp_level = opts_src->comp_level;
    opts_dst->addblk = opts_src->addblk;
    opts_dst->addblk_comp = opts_src->addblk_comp;
    opts_dst->addblk_comp_level = opts_src->addblk_comp_level;
    opts_dst->mbytes = opts_src->mbytes;

    free(opts_dst->seqfile);
    free(opts_dst->oldrpmprint);
    free(opts_dst->oldpatchrpm);
    opts_dst->seqfile = NULL;
    opts_dst->oldrpmprint = NULL;
    opts_dst->oldpatchrpm = NULL;

    if (opts_src->seqfile != NULL) {
        if ((opts_dst->seqfile = malloc(strlen(opts_src->seqfile) + 1)) == NULL)
            return DRPM_ERR_OK;
        strcpy(opts_dst->seqfile, opts_src->seqfile);
    }

    if (opts_src->oldrpmprint != NULL) {
        if ((opts_dst->oldrpmprint = malloc(strlen(opts_src->oldrpmprint) + 1)) == NULL)
            return DRPM_ERR_OK;
        strcpy(opts_dst->oldrpmprint, opts_src->oldrpmprint);
    }

    if (opts_src->oldpatchrpm != NULL) {
        if ((opts_dst->oldpatchrpm = malloc(strlen(opts_src->oldpatchrpm) + 1)) == NULL)
            return DRPM_ERR_OK;
        strcpy(opts_dst->oldpatchrpm, opts_src->oldpatchrpm);
    }

    return DRPM_ERR_OK;
}

int drpm_make_options_set_type(struct drpm_make_options *opts, unsigned short type)
{
    if (opts == NULL)
        return DRPM_ERR_ARGS;

    switch (type) {
    case DRPM_TYPE_STANDARD:
        opts->rpm_only = false;
        break;
    case DRPM_TYPE_RPMONLY:
        opts->rpm_only = true;
        break;
    default:
        return DRPM_ERR_ARGS;
    }

    return DRPM_ERR_OK;
}

int drpm_make_options_set_version(struct drpm_make_options *opts, unsigned short version)
{
    if (opts == NULL || version < 1 || version > 3)
        return DRPM_ERR_ARGS;

    opts->version = version;

    return DRPM_ERR_OK;
}

int drpm_make_options_set_delta_comp(struct drpm_make_options *opts, unsigned short comp, unsigned short level)
{
    if (opts == NULL ||
        (level != DRPM_COMP_LEVEL_DEFAULT && (level < 1 || level > 9)))
        return DRPM_ERR_ARGS;

    switch (comp) {
    case DRPM_COMP_NONE:
    case DRPM_COMP_GZIP:
    case DRPM_COMP_BZIP2:
    case DRPM_COMP_LZMA:
    case DRPM_COMP_XZ:
    case DRPM_COMP_LZIP:
        opts->comp_from_rpm = false;
        opts->comp = comp;
        opts->comp_level = level;
        break;
    default:
        return DRPM_ERR_ARGS;
    }

    return DRPM_ERR_OK;
}

int drpm_make_options_get_delta_comp_from_rpm(struct drpm_make_options *opts)
{
    if (opts == NULL)
        return DRPM_ERR_ARGS;

    opts->comp_from_rpm = true;

    return DRPM_ERR_OK;
}

int drpm_make_options_forbid_addblk(struct drpm_make_options *opts)
{
    if (opts == NULL)
        return DRPM_ERR_ARGS;

    opts->addblk = false;

    return DRPM_ERR_OK;
}

int drpm_make_options_set_addblk_comp(struct drpm_make_options *opts, unsigned short comp, unsigned short level)
{
    if (opts == NULL ||
        (level != DRPM_COMP_LEVEL_DEFAULT && (level < 1 || level > 9)))
        return DRPM_ERR_ARGS;

    switch (comp) {
    case DRPM_COMP_NONE:
    case DRPM_COMP_GZIP:
    case DRPM_COMP_BZIP2:
    case DRPM_COMP_LZMA:
    case DRPM_COMP_XZ:
    case DRPM_COMP_LZIP:
        opts->addblk = true;
        opts->addblk_comp = comp;
        opts->addblk_comp_level = level;
        break;
    default:
        return DRPM_ERR_ARGS;
    }

    return DRPM_ERR_OK;
}

int drpm_make_options_set_seqfile(struct drpm_make_options *opts, const char *seqfile)
{
    char *tmp;

    if (opts == NULL)
        return DRPM_ERR_ARGS;

    if (seqfile == NULL) {
        free(opts->seqfile);
        opts->seqfile = NULL;
    } else {
        if (opts->seqfile == NULL || strlen(opts->seqfile) < strlen(seqfile)) {
            if ((tmp = realloc(opts->seqfile, strlen(seqfile) + 1)) == NULL)
                return DRPM_ERR_MEMORY;
            opts->seqfile = tmp;
        }
        strcpy(opts->seqfile, seqfile);
    }

    return DRPM_ERR_OK;
}

int drpm_make_options_add_patches(struct drpm_make_options *opts, const char *oldrpmprint, const char *oldpatchrpm)
{
    char *tmp;

    if (opts == NULL || oldrpmprint == NULL || oldpatchrpm == NULL)
        return DRPM_ERR_ARGS;

    if (opts->oldrpmprint == NULL || strlen(opts->oldrpmprint) < strlen(oldrpmprint)) {
        if ((tmp = realloc(opts->oldrpmprint, strlen(oldrpmprint) + 1)) == NULL)
            return DRPM_ERR_MEMORY;
        opts->oldrpmprint = tmp;
    }
    if (opts->oldpatchrpm == NULL || strlen(opts->oldpatchrpm) < strlen(oldpatchrpm)) {
        if ((tmp = realloc(opts->oldpatchrpm, strlen(oldpatchrpm) + 1)) == NULL)
            return DRPM_ERR_MEMORY;
        opts->oldpatchrpm = tmp;
    }

    strcpy(opts->oldrpmprint, oldrpmprint);
    strcpy(opts->oldpatchrpm, oldpatchrpm);

    return DRPM_ERR_OK;
}

// TODO: not yet used
int drpm_make_options_set_memlimit(struct drpm_make_options *opts, unsigned mbytes)
{
    if (opts == NULL)
        return DRPM_ERR_ARGS;

    opts->mbytes = mbytes;

    return DRPM_ERR_OK;
}
