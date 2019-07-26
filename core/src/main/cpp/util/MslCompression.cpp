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

#include <util/MslCompression.h>
#include <MslError.h>
#include <MslException.h>
#include <map>
#include <memory>
#include <utility>

using namespace std;

namespace netflix {
namespace msl {
namespace util {

namespace MslCompression {

namespace {

/** Registered compression implementations. */
map<MslConstants::CompressionAlgorithm,shared_ptr<CompressionImpl>>& impls() {
	static map<MslConstants::CompressionAlgorithm,shared_ptr<CompressionImpl>> impls;
	return impls;
}
/** Maximum deflate ratio. Volatile should be good enough. */
volatile uint32_t maxDeflateRatio = 200;

} // namespace anonymous

void registerImpl(const MslConstants::CompressionAlgorithm& algo, shared_ptr<CompressionImpl> impl)
{
	if (!impl)
		impls().erase(algo);
	else
		impls().insert(make_pair(algo, impl));
}

void setMaxDeflateRatio(uint32_t deflateRatio)
{
    if (deflateRatio < 1)
        throw IllegalArgumentException("The maximum deflate ratio must be at least one.");
    maxDeflateRatio = deflateRatio;
}

shared_ptr<ByteArray> compress(const MslConstants::CompressionAlgorithm& compressionAlgo,
        const ByteArray& data)
{
	map<MslConstants::CompressionAlgorithm,shared_ptr<CompressionImpl>>::const_iterator impl = impls().find(compressionAlgo);
	if (impl == impls().end())
		throw MslException(MslError::UNSUPPORTED_COMPRESSION, compressionAlgo.toString());
	try {
		shared_ptr<ByteArray> compressed = impl->second->compress(data);
		return (compressed && compressed->size() < data.size()) ? compressed : NULL;
	} catch (const Exception& e) {
        throw MslException(MslError::COMPRESSION_ERROR, string("algo ") + compressionAlgo.toString(), e);
	}
}

shared_ptr<ByteArray> uncompress(const MslConstants::CompressionAlgorithm& compressionAlgo,
        const ByteArray& data)
{
	map<MslConstants::CompressionAlgorithm,shared_ptr<CompressionImpl>>::const_iterator impl = impls().find(compressionAlgo);
	if (impl == impls().end())
		throw MslException(MslError::UNSUPPORTED_COMPRESSION, compressionAlgo.toString());
	try {
		return impl->second->uncompress(data, maxDeflateRatio);
	} catch (const Exception& e) {
        throw MslException(MslError::UNCOMPRESSION_ERROR, string("algo ") + compressionAlgo.toString(), e);
	}
}

} // namespace MslCompression

}}} // namespace netflix::msl::util
