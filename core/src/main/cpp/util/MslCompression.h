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

#ifndef SRC_UTIL_MSLCOMPRESSION_H_
#define SRC_UTIL_MSLCOMPRESSION_H_

#include <MslConstants.h>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {

typedef std::vector<uint8_t> ByteArray;

namespace util {

class MslContext;

/**
 * <p>Data compression and uncompression. Can be configured with a backing
 * implementation.</p>
 *
 * <p>This class is thread-safe.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
namespace MslCompression {

/**
 * <p>A data compression implementation. Implementations must be thread-
 * safe.</p>
 *
 * @interface
 */
class CompressionImpl
{
public:
	virtual ~CompressionImpl() {}

    /**
     * <p>Compress the provided data.</p>
     *
     * @param data the data to compress.
     * @return the compressed data. May also return {@code null} if the
     *         compressed data would exceed the original data size.
     * @throws IOException if there is an error compressing the data.
     */
	virtual std::shared_ptr<ByteArray> compress(const ByteArray& data) = 0;

	/**
	 * <p>Uncompress the provided data.</p>
	 *
	 * <p>If the uncompressed data ever exceeds the maximum deflate ratio
	 * then uncompression must abort and an exception thrown.</p>
	 *
	 * @param data the data to uncompress.
	 * @param maxDeflateRatio the maximum deflate ratio.
	 * @return the uncompressed data.
	 * @throws IOException if there is an error uncompressing the data or
	 *         if the ratio of uncompressed data to the compressed data
	 *         ever exceeds the specified deflate ratio.
	 */
	virtual std::shared_ptr<ByteArray> uncompress(const ByteArray& data, uint32_t maxDeflateRatio) = 0;
};

/**
 * <p>Register a compression algorithm implementation. Pass {@code null} to
 * remove an implementation.</p>
 *
 * @param algo the compression algorithm.
 * @param impl the data compression implementation. May be {@code null}.
 */
void registerImpl(const MslConstants::CompressionAlgorithm& algo, std::shared_ptr<CompressionImpl> impl);

/**
 * <p>Sets the maximum deflate ratio used during uncompression. If the
 * ratio is exceeded uncompression will abort.</p>
 *
 * @param deflateRatio the maximum deflate ratio.
 * @throws IllegalArgumentException if the specified ratio is less than
 *         one.
 */
void setMaxDeflateRatio(uint32_t deflateRatio);

/**
 * Compress the provided data using the specified compression algorithm.
 *
 * @param compressionAlgo the compression algorithm.
 * @param data the data to compress.
 * @return the compressed data or null if the compressed data would be larger than the
 *         uncompressed data.
 * @throws MslException if there is an error compressing the data.
 */
std::shared_ptr<ByteArray> compress(const MslConstants::CompressionAlgorithm& compressionAlgo, const ByteArray& data);

/**
 * Uncompress the provided data using the specified compression algorithm.
 *
 * @param compressionAlgo the compression algorithm.
 * @param data the data to uncompress.
 * @return the uncompressed data.
 * @throws MslException if there is an error uncompressing the data.
 */
std::shared_ptr<ByteArray> uncompress(const MslConstants::CompressionAlgorithm& compressionAlgo, const ByteArray& data);

} // namespace MslCompression

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_MSLCOMPRESSION_H_ */
