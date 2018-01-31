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
#include <IllegalArgumentException.h>
#include <util/Base64Secure.h>
#include <algorithm>
#include <ctype.h>
#include <regex>
#include <string>

using namespace std;

namespace netflix {
namespace msl {
namespace util {

namespace // anonymous
{
Base64Secure impl_;
} // namespace anonymous

namespace Base64 {

shared_ptr<string> encode(std::shared_ptr<ByteArray> b) {
	if (!b)
		throw IllegalArgumentException("Base64::encode() argument is null");
	return impl_.encode(*b);
}

shared_ptr<string> encode(const ByteArray& b) {
	return impl_.encode(b);
}

shared_ptr<ByteArray> decode(std::shared_ptr<string> s) {
	if (!s)
		throw IllegalArgumentException("Base64::decode() argument is null");
	return impl_.decode(*s);
}

shared_ptr<ByteArray> decode(const string& s) {
	return impl_.decode(s);
}

} // namespace Base64
} // namespace util
} // namespace msl
} // namespace netflix
