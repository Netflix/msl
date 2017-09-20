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

#include <io/ByteArrayOutputStream.h>
#include <IllegalArgumentException.h>
#include <IOException.h>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

bool ByteArrayOutputStream::close()
{
	closed_ = true;
	return true;
}

size_t ByteArrayOutputStream::write(const ByteArray& data, size_t off, size_t len, int /*timeout*/)
{
	if (closed_)
		throw IOException("Stream is already closed.");

	if (off + len > data.size())
		throw IllegalArgumentException("Offset plus length cannot be greater than the array length.");

	result_->insert(result_->end(), data.begin() + static_cast<ptrdiff_t>(off), data.begin() + static_cast<ptrdiff_t>(off) + static_cast<ptrdiff_t>(len));
	return len;
}

bool ByteArrayOutputStream::flush(int /*timeout*/)
{
	return true;
}

shared_ptr<ByteArray> ByteArrayOutputStream::toByteArray()
{
	// Return a copy so the caller always has the data they expected when they
	// called this function.
	return make_shared<ByteArray>(result_->begin(), result_->end());
}

}}} // namespace netflix::msl::io
