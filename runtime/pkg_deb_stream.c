/* SPDX-License-Identifier: MIT
 * Incremental, bounded interface to unmodified upstream codecs. No I/O.
 * Each call borrows buffers; no caller buffer is retained between calls.
 * Results: 0 continue, 1 complete, 2 malformed/state, 3 budget,
 *          4 unsupported, 5 internal failure. Errors report zero bytes.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>
#include <zstd.h>

#define STREAM_MAX (UINT64_C(8) * 1024 * 1024 * 1024)
#define BLOCK_MAX 65536U
struct nia_deb_stream {
    int codec, terminal;
    uint64_t expected, limit, read, written;
    z_stream gzip;
    bz_stream bzip;
    lzma_stream lzma;
    ZSTD_DStream *zstd;
};

void nia_deb_stream_free(void *handle)
{
    struct nia_deb_stream *s = handle;
    if (!s) return;
    if (s->gzip.state) inflateEnd(&s->gzip);
    if (s->bzip.state) BZ2_bzDecompressEnd(&s->bzip);
    lzma_end(&s->lzma);
    ZSTD_freeDStream(s->zstd);
    free(s);
}

int nia_deb_stream_new(int codec, uint64_t expected, uint64_t limit, void **result)
{
    struct nia_deb_stream *s;
    int status = 0;
    if (!result) return 2;
    *result = NULL;
    if (expected > STREAM_MAX || limit > STREAM_MAX) return 3;
    if (codec != 0 && codec != 1 && codec != 2 && codec != 5 && codec != 6 && codec != 14)
        return 4;
    s = calloc(1, sizeof(*s));
    if (!s) return 3;
    s->codec = codec; s->expected = expected; s->limit = limit;
    s->lzma = (lzma_stream)LZMA_STREAM_INIT;
    if (codec == 1) {
        int rc = inflateInit2(&s->gzip, 15 + 16);
        if (rc != Z_OK) status = rc == Z_MEM_ERROR ? 3 : 5;
    } else if (codec == 2) {
        int rc = BZ2_bzDecompressInit(&s->bzip, 0, 0);
        if (rc != BZ_OK) status = rc == BZ_MEM_ERROR ? 3 : 5;
    } else if (codec == 5 || codec == 6) {
        lzma_ret rc = codec == 5 ? lzma_alone_decoder(&s->lzma, UINT64_C(128) * 1024 * 1024) :
            lzma_stream_decoder(&s->lzma, UINT64_C(128) * 1024 * 1024, LZMA_TELL_UNSUPPORTED_CHECK);
        if (rc != LZMA_OK) status = rc == LZMA_MEM_ERROR ? 3 : 5;
    } else if (codec == 14) {
        s->zstd = ZSTD_createDStream();
        if (!s->zstd) status = 3;
        else if (ZSTD_isError(ZSTD_DCtx_setParameter(s->zstd, ZSTD_d_windowLogMax, 27))) status = 5;
    }
    if (status) { nia_deb_stream_free(s); return status; }
    *result = s;
    return 0;
}

int nia_deb_stream_step(void *handle, const unsigned char *input, size_t input_size,
                        size_t *consumed, unsigned char *output, size_t capacity, size_t *produced)
{
    struct nia_deb_stream *s = handle;
    size_t take = 0, put = 0, space;
    int status = 0, finished = 0, final_input;
    if (consumed) *consumed = 0;
    if (produced) *produced = 0;
    if (!s || s->terminal) return 2;
    if (!consumed || !produced || !output || (!input && input_size) || !capacity ||
        capacity > BLOCK_MAX || input_size > BLOCK_MAX || input_size > s->expected - s->read) {
        s->terminal = 1; return 2;
    }
    final_input = input_size == s->expected - s->read;
    /* One extra output byte distinguishes an exact limit plus trailer from overflow. */
    space = capacity;
    if (space > s->limit - s->written + 1) space = (size_t)(s->limit - s->written + 1);
    if (s->codec == 0) {
        put = take = input_size < space ? input_size : space;
        if (take) memcpy(output, input, take);
        finished = final_input && take == input_size;
    } else if (s->codec == 1) {
        int rc;
        s->gzip.next_in = (Bytef *)input; s->gzip.avail_in = (uInt)input_size;
        s->gzip.next_out = output; s->gzip.avail_out = (uInt)space;
        rc = inflate(&s->gzip, Z_NO_FLUSH);
        take = input_size - s->gzip.avail_in; put = space - s->gzip.avail_out;
        s->gzip.next_in = NULL; s->gzip.next_out = NULL;
        s->gzip.avail_in = 0; s->gzip.avail_out = 0;
        if (rc == Z_STREAM_END) finished = 1;
        else if (rc != Z_OK && rc != Z_BUF_ERROR) status = rc == Z_MEM_ERROR ? 3 : 2;
    } else if (s->codec == 2) {
        int rc;
        s->bzip.next_in = (char *)input; s->bzip.avail_in = (unsigned)input_size;
        s->bzip.next_out = (char *)output; s->bzip.avail_out = (unsigned)space;
        rc = BZ2_bzDecompress(&s->bzip);
        take = input_size - s->bzip.avail_in; put = space - s->bzip.avail_out;
        s->bzip.next_in = NULL; s->bzip.next_out = NULL;
        s->bzip.avail_in = 0; s->bzip.avail_out = 0;
        if (rc == BZ_STREAM_END) finished = 1;
        else if (rc != BZ_OK) status = rc == BZ_MEM_ERROR ? 3 : 2;
    } else if (s->codec == 5 || s->codec == 6) {
        lzma_ret rc;
        s->lzma.next_in = input; s->lzma.avail_in = input_size;
        s->lzma.next_out = output; s->lzma.avail_out = space;
        rc = lzma_code(&s->lzma, final_input ? LZMA_FINISH : LZMA_RUN);
        take = input_size - s->lzma.avail_in; put = space - s->lzma.avail_out;
        s->lzma.next_in = NULL; s->lzma.next_out = NULL;
        s->lzma.avail_in = 0; s->lzma.avail_out = 0;
        if (rc == LZMA_STREAM_END) finished = 1;
        else if (rc != LZMA_OK && rc != LZMA_BUF_ERROR)
            status = rc == LZMA_MEM_ERROR || rc == LZMA_MEMLIMIT_ERROR ? 3 :
                rc == LZMA_UNSUPPORTED_CHECK ? 4 : 2;
    } else {
        ZSTD_inBuffer in = {input, input_size, 0};
        ZSTD_outBuffer out = {output, space, 0};
        size_t rc = ZSTD_decompressStream(s->zstd, &out, &in);
        take = in.pos; put = out.pos;
        if (ZSTD_isError(rc)) status = 2;
        else if (!rc) finished = 1;
    }
    if (put > s->limit - s->written) status = 3;
    if (finished && take != s->expected - s->read) status = 2;
    if (!finished && !take && !put && (final_input || input_size)) status = 2;
    if (status) { s->terminal = 1; return status; }
    s->read += take; s->written += put;
    *consumed = take; *produced = put;
    if (finished) { s->terminal = 1; return 1; }
    return 0;
}
