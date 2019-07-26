/**
 * Copyright (c) 2017-2018 Netflix, Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <util/GzipCompression.h>
#include <IOException.h>

#include <cstring>
#include <memory>
#include <vector>
#include <zlib.h>

using namespace std;
using namespace netflix::msl;

namespace {

// --- GZIP compress / decompress ---

// Original: http://panthema.net/2007/0328-ZLibString.html, Timo Bingmann
// Edited to support gzip: http://blog.cppse.nl/deflate-and-gzip-compress-and-decompress-functions, Ray Burgemeestre
// License: http://www.boost.org/LICENSE_1_0.txt
// Edited to support vector instead of string.

// Found these here http://mail-archives.apache.org/mod_mbox/trafficserver-dev/201110.mbox/%3CCACJPjhYf=+br1W39vyazP=ix
//eQZ-4Gh9-U6TtiEdReG3S4ZZng@mail.gmail.com%3E
#define MOD_GZIP_ZLIB_WINDOWSIZE 15
#define MOD_GZIP_ZLIB_CFACTOR    9
#define MOD_GZIP_ZLIB_BSIZE      8096

const size_t BUFSIZE = 16 * 1024;

void compress_gzip(const vector<uint8_t>& in, vector<uint8_t>& out,
        int compressionlevel = Z_BEST_COMPRESSION)
{
	vector<uint8_t> tmpBuf(BUFSIZE);
    z_stream zs;                        // z_stream is zlib's control structure
    memset(&zs, 0, sizeof(zs));

    if (deflateInit2(&zs,
                     compressionlevel,
                     Z_DEFLATED,
                     MOD_GZIP_ZLIB_WINDOWSIZE + 16,
                     MOD_GZIP_ZLIB_CFACTOR,
                     Z_DEFAULT_STRATEGY) != Z_OK
    ) {
        throw(runtime_error("deflateInit2 failed while compressing."));
    }

    zs.next_in = (Bytef*)in.data();
    zs.avail_in = (uInt)in.size();           // set the z_stream's input

    int ret;
    vector<uint8_t> tmpOut;

    // retrieve the compressed bytes blockwise
    do {
        zs.next_out = reinterpret_cast<Bytef*>(&tmpBuf[0]);
        zs.avail_out = (uInt)(sizeof(uint8_t) * tmpBuf.size());

        ret = deflate(&zs, Z_FINISH);

        if (tmpOut.size() < zs.total_out) {
            // append the block to the output
            tmpOut.insert(tmpOut.end(), &tmpBuf[0], &tmpBuf[0] + zs.total_out - tmpOut.size());
        }
    } while (ret == Z_OK);

    deflateEnd(&zs);

    if (ret != Z_STREAM_END) {          // an error occurred that was not EOF
        ostringstream oss;
        oss << "Exception during zlib compression: (" << ret << ") " << zs.msg;
        throw(runtime_error(oss.str()));
    }

    out.swap(tmpOut);
}

void decompress_gzip(const vector<uint8_t>& in, vector<uint8_t>& out, uint32_t maxDeflateRatio)
{
	vector<uint8_t> tmpBuf(BUFSIZE);
    z_stream zs;                        // z_stream is zlib's control structure
    memset(&zs, 0, sizeof(zs));

    if (inflateInit2(&zs, MOD_GZIP_ZLIB_WINDOWSIZE + 16) != Z_OK)
        throw(runtime_error("inflateInit failed while decompressing."));

    zs.next_in = (Bytef*)in.data();
    zs.avail_in = (uInt)in.size();

    int ret;
    vector<uint8_t> tmpOut;

    // get the decompressed bytes blockwise using repeated calls to inflate
    do {
        // Uncompress.
        zs.next_out = reinterpret_cast<Bytef*>(&tmpBuf[0]);
        zs.avail_out = (uInt)(sizeof(uint8_t) * tmpBuf.size());

        ret = inflate(&zs, 0);

        if (tmpOut.size() < zs.total_out) {
            // Check if the deflate ratio has been exceeded.
            if (zs.total_out > maxDeflateRatio * in.size()) {
                ostringstream oss;
                oss << "Deflate ratio " << maxDeflateRatio << " exceeded. Aborting uncompression.";
                throw IOException(oss.str());
            }

            // Save the uncompressed data for return.
            tmpOut.insert(tmpOut.end(), &tmpBuf[0], &tmpBuf[0] + zs.total_out - tmpOut.size());
        }

    } while (ret == Z_OK);

    inflateEnd(&zs);

    if (ret != Z_STREAM_END) {          // an error occurred that was not EOF
        ostringstream oss;
        oss << "Exception during zlib decompression: (" << ret << ") "
            << zs.msg;
        throw(runtime_error(oss.str()));
    }

    out.swap(tmpOut);
}

} // namespace anonymous

namespace netflix {
namespace msl {
namespace util {

shared_ptr<ByteArray> GzipCompression::compress(const ByteArray& data)
{
	shared_ptr<ByteArray> compressed = make_shared<ByteArray>();
	compress_gzip(data, *compressed);
	return compressed;
}

shared_ptr<ByteArray> GzipCompression::uncompress(const ByteArray& data, uint32_t maxDeflateRatio)
{
	shared_ptr<ByteArray> decompressed = make_shared<ByteArray>();
	decompress_gzip(data, *decompressed, maxDeflateRatio);
	return decompressed;
}

}}} // namespace netflix::msl::util
