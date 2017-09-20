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

#include <util/Base64.h>

namespace netflix {
namespace msl {
namespace util {

/**
 * <p>Base64 encoder/decoder implementation that strictly enforces the validity
 * of the encoding and does not exit early if an error is encountered.
 * Whitespace (space, tab, newline, carriage return) are skipped.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class Base64Secure : public Base64Impl
{
public:
	virtual ~Base64Secure() {}

    /** @inheritDoc */
    virtual std::shared_ptr<std::string> encode(const ByteArray& b);

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> decode(const std::string& s);
};

}}} // namespace netflix::msl::util
