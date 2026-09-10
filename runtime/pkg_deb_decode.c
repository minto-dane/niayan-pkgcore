/* SPDX-License-Identifier: BSD-3-Clause
 * Thin bounded interface to unmodified upstream codecs. No files or processes.
 * Return: 0 success, 1 malformed/trailing stream, 2 budget, 3 deadline,
 * 4 unsupported codec/check, 5 internal failure. Output length is zero on error.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <zlib.h>
#include <lzma.h>
#include <zstd.h>

static int time_status(uint64_t deadline)
{
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0 || now.tv_sec < 0)
        return 5;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000 >= deadline ? 3 : 0;
}

static size_t chunk(size_t remaining)
{
    return remaining < 65536 ? remaining : 65536;
}

int nia_deb_decode(int codec, const unsigned char *input, size_t input_size,
                   unsigned char *output, size_t capacity, size_t *used,
                   uint64_t deadline)
{
    int result;
    size_t written = 0;
    if (!used)
        return 1;
    *used = 0;
    if (!input || !output || input_size == 0 || input_size > 16U * 1024U * 1024U ||
        capacity == 0 || capacity > 32U * 1024U * 1024U + 1)
        return 2;
    result = time_status(deadline);
    if (result)
        return result;
    if (codec == 0) {
        if (input_size > capacity)
            return 2;
        while (written < input_size) {
            size_t n = chunk(input_size - written);
            result = time_status(deadline);
            if (result)
                return result;
            memcpy(output + written, input + written, n);
            written += n;
        }
    } else if (codec == 1) {
        z_stream stream = {0};
        int rc = inflateInit2(&stream, 15 + 16); /* gzip including header/trailer CRC */
        if (rc != Z_OK)
            return rc == Z_MEM_ERROR ? 2 : 5;
        stream.next_in = (Bytef *)input;
        stream.avail_in = (uInt)input_size;
        for (;;) {
            size_t available = chunk(capacity - written);
            uLong old_in = stream.total_in;
            result = time_status(deadline);
            if (result)
                break;
            if (!available) { result = 2; break; }
            stream.next_out = output + written;
            stream.avail_out = (uInt)available;
            rc = inflate(&stream, Z_NO_FLUSH);
            written += available - stream.avail_out;
            if (rc == Z_STREAM_END) {
                result = stream.total_in == input_size ? 0 : 1;
                break;
            }
            if (rc != Z_OK) { result = rc == Z_MEM_ERROR ? 2 : 1; break; }
            if (old_in == stream.total_in && stream.avail_out == available) { result = 1; break; }
        }
        if (inflateEnd(&stream) != Z_OK && result == 0)
            result = 5;
        if (result)
            return result;
    } else if (codec == 6) {
        lzma_stream stream = LZMA_STREAM_INIT;
        lzma_ret rc = lzma_stream_decoder(&stream, UINT64_C(128) * 1024 * 1024,
                                          LZMA_TELL_UNSUPPORTED_CHECK);
        if (rc != LZMA_OK)
            return rc == LZMA_MEM_ERROR ? 2 : 5;
        stream.next_in = input;
        stream.avail_in = input_size;
        for (;;) {
            size_t available = chunk(capacity - written);
            uint64_t old_in = stream.total_in;
            result = time_status(deadline);
            if (result)
                break;
            if (!available) { result = 2; break; }
            stream.next_out = output + written;
            stream.avail_out = available;
            rc = lzma_code(&stream, LZMA_FINISH);
            written += available - stream.avail_out;
            if (rc == LZMA_STREAM_END) {
                result = stream.total_in == input_size ? 0 : 1;
                break;
            }
            if (rc != LZMA_OK) {
                result = rc == LZMA_MEM_ERROR || rc == LZMA_MEMLIMIT_ERROR ? 2 :
                         rc == LZMA_UNSUPPORTED_CHECK ? 4 : 1;
                break;
            }
            if (old_in == stream.total_in && stream.avail_out == available) { result = 1; break; }
        }
        lzma_end(&stream);
        if (result)
            return result;
    } else if (codec == 14) {
        ZSTD_DStream *stream = ZSTD_createDStream();
        ZSTD_inBuffer in = {input, input_size, 0};
        if (!stream)
            return 2;
        if (ZSTD_isError(ZSTD_DCtx_setParameter(stream, ZSTD_d_windowLogMax, 27))) {
            ZSTD_freeDStream(stream);
            return 5;
        }
        for (;;) {
            size_t rc, old_in = in.pos;
            ZSTD_outBuffer out = {output + written, chunk(capacity - written), 0};
            result = time_status(deadline);
            if (result)
                break;
            if (!out.size) { result = 2; break; }
            rc = ZSTD_decompressStream(stream, &out, &in);
            written += out.pos;
            if (ZSTD_isError(rc)) { result = 1; break; }
            if (rc == 0) { result = in.pos == input_size ? 0 : 1; break; }
            if (old_in == in.pos && out.pos == 0) { result = 1; break; }
        }
        ZSTD_freeDStream(stream);
        if (result)
            return result;
    } else {
        return 4;
    }
    result = time_status(deadline);
    if (result)
        return result;
    *used = written;
    return 0;
}
