/*
    Authors:
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2004,2005 Michael Schroeder (mls@suse.de)
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

#include "drpm.h"
#include "drpm_private.h"

#include <string.h>
#include <openssl/md5.h>

#define BUFFER_SIZE 4096

void free_deltarpm(struct deltarpm *delta)
{
    if (delta->type == DRPM_TYPE_STANDARD) {
        rpm_destroy(&delta->head.rpm_head);
    } else if (delta->type == DRPM_TYPE_RPMONLY) {
        free(delta->head.tgt_nevr);
        delta->head.tgt_nevr = NULL;
    }
    free(delta->src_nevr);
    free(delta->sequence);
    free(delta->tgt_comp_param);
    free(delta->offadjs);
    free(delta->tgt_lead);
    free(delta->int_copies);
    free(delta->ext_copies);
    free(delta->add_data);
    free(delta->int_data);

    delta->src_nevr = NULL;
    delta->sequence_len = 0;
    delta->sequence = NULL;
    delta->tgt_size = 0;
    delta->tgt_comp_param_len = 0;
    delta->tgt_comp_param = NULL;
    delta->tgt_header_len = 0;
    delta->offadjn = 0;
    delta->offadjs = NULL;
    delta->tgt_lead_len = 0;
    delta->tgt_lead = NULL;
    delta->payload_fmt_off = 0;
    delta->inn = 0;
    delta->outn = 0;
    delta->int_copies = NULL;
    delta->ext_copies = NULL;
    delta->ext_data_len = 0;
    delta->add_data_len = 0;
    delta->add_data = NULL;
    delta->int_data_len = 0;
    delta->int_data = NULL;
}

int write_nodiff_deltarpm(struct deltarpm *delta, const char *rpm_filename)
{
    struct rpm *solo_rpm;
    MD5_CTX seq_md5;
    MD5_CTX full_md5;
    char *nevr = NULL;
    int error = DRPM_ERR_OK;

    if ((error = rpm_read(&solo_rpm, rpm_filename, true)) != DRPM_ERR_OK ||
        (error = rpm_fetch_lead_and_signature(solo_rpm, &delta->tgt_lead, &delta->tgt_lead_len)) != DRPM_ERR_OK)
        goto cleanup;

    if (MD5_Init(&seq_md5) != 1 || MD5_Init(&full_md5) != 1) {
        error = DRPM_ERR_CONFIG;
        goto cleanup;
    }

    if ((error = rpm_add_lead_to_md5(solo_rpm, &full_md5)) != DRPM_ERR_OK ||
        (error = rpm_add_signature_to_md5(solo_rpm, &seq_md5)) != DRPM_ERR_OK ||
        (error = rpm_add_signature_to_md5(solo_rpm, &full_md5)) != DRPM_ERR_OK ||
        (error = rpm_add_header_to_md5(solo_rpm, &seq_md5)) != DRPM_ERR_OK ||
        (error = rpm_add_header_to_md5(solo_rpm, &full_md5)) != DRPM_ERR_OK ||
        (error = rpm_add_archive_to_md5(solo_rpm, &seq_md5)) != DRPM_ERR_OK ||
        (error = rpm_add_archive_to_md5(solo_rpm, &full_md5)) != DRPM_ERR_OK)
        goto cleanup;

    if ((delta->sequence = malloc(MD5_DIGEST_LENGTH)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    delta->sequence_len = MD5_DIGEST_LENGTH;

    if (MD5_Final(delta->sequence, &seq_md5) != 1 ||
        MD5_Final(delta->tgt_md5, &full_md5) != 1) {
        error = DRPM_ERR_CONFIG;
        goto cleanup;
    }

    if ((error = rpm_get_nevr(solo_rpm, &nevr)) != DRPM_ERR_OK)
        goto cleanup;

    if ((delta->src_nevr = malloc(strlen(nevr))) == NULL ||
        (delta->head.tgt_nevr = malloc(strlen(nevr))) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    strcpy(delta->src_nevr, nevr);
    strcpy(delta->head.tgt_nevr, nevr);

    delta->tgt_size = rpm_size_full(solo_rpm);
    delta->tgt_header_len = rpm_size_header(solo_rpm);

    delta->tgt_comp_param_len = 0;
    delta->tgt_comp_param = NULL;
    delta->offadjn = 0;
    delta->offadjs = NULL;
    delta->payload_fmt_off = 0;
    delta->inn = 0;
    delta->outn = 0;
    delta->int_copies = NULL;
    delta->ext_copies = NULL;
    delta->ext_data_len = 0;
    delta->add_data_len = 0;
    delta->add_data = NULL;
    delta->int_data_len = 0;
    delta->int_data = NULL;

    error = write_deltarpm(*delta);

cleanup:
    free(nevr);
    rpm_destroy(&solo_rpm);
    free_deltarpm(delta);

    return error;
}
