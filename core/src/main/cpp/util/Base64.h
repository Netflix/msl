/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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
#ifndef Netflix_Base_Base64_h_
#define Netflix_Base_Base64_h_

#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

namespace netflix {
namespace msl {

typedef std::vector<uint8_t> ByteArray;

namespace util {

/**
 * <p>A Base64 encoder/decoder implementation. Implementations must be
 * thread-safe.</p>
 */
class Base64Impl
{
public:
	virtual ~Base64Impl() {}

	/**
	 * <p>Base64 encodes binary data.</p>
	 *
	 * @param b the binary data.
	 * @return the Base64-encoded binary data.
	 */
	 virtual std::shared_ptr<std::string> encode(const ByteArray& b) = 0;

	/**
	 * <p>Decodes a Base64-encoded string into its binary form.</p>
	 *
	 * @param s the Base64-encoded string.
	 * @return the binary data.
	 * @throws IllegalArgumentException if the argument is not a valid
	 *         Base64-encoded string. The empty string is considered valid.
	 */
	virtual std::shared_ptr<ByteArray> decode(const std::string& s) = 0;
};

namespace Base64
{
    /**
     * <p>Base64 encodes binary data.</p>
     *
     * @param b the binary data.
     * @return the Base64-encoded binary data.
     */
	std::shared_ptr<std::string> encode(std::shared_ptr<ByteArray> b);
	std::shared_ptr<std::string> encode(const ByteArray& b);

    /**
     * <p>Decodes a Base64-encoded string into its binary form.</p>
     *
     * @param s the Base64-encoded string.
     * @return the binary data.
     * @throws IllegalArgumentException if the argument is not a valid Base64-
     *         encoded string.
     */
	std::shared_ptr<ByteArray> decode(std::shared_ptr<std::string> s);
	std::shared_ptr<ByteArray> decode(const std::string& s);
}

}}} // namespace netflix::msl::util

#endif // Netflix_Base_Base64_h_
