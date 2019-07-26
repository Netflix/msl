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

#ifndef SRC_UTIL_GZIPCOMPRESSION_H_
#define SRC_UTIL_GZIPCOMPRESSION_H_

#include <util/MslCompression.h>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace util {

class GzipCompression : public MslCompression::CompressionImpl
{
public:
	virtual ~GzipCompression() {}

    /** @inheritDoc */
	virtual std::shared_ptr<ByteArray> compress(const ByteArray& data);

    /** @inheritDoc */
	virtual std::shared_ptr<ByteArray> uncompress(const ByteArray& data, uint32_t maxDeflateRatio);
};

}}} // namespace netflix::msl::util

#endif /* SRC_UTIL_GZIPCOMPRESSION_H_ */
