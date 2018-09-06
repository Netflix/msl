/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

#include <io/ByteArrayInputStream.h>
#include <IOException.h>
#include <algorithm>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

bool ByteArrayInputStream::close(int /*timeout*/)
{
    closed_ = true;
    return true;
}

void ByteArrayInputStream::mark(size_t /*readlimit*/)
{
    mark_ = currentPosition_;
}

void ByteArrayInputStream::reset()
{
    if (closed_)
        throw IOException("Stream is already closed.");

    currentPosition_ = mark_;
}

int ByteArrayInputStream::read(ByteArray& out, size_t offset, size_t len, int /* timeout */)
{
	if (closed_)
		throw IOException("Stream is already closed.");

	if (currentPosition_ == data_->size())
		return -1;

	if (len > data_->size() - currentPosition_)
		len = data_->size() - currentPosition_;
	if (out.size() < offset + len)
		out.resize(offset + len);
	copy(data_->begin() + static_cast<ptrdiff_t>(currentPosition_), data_->begin() + static_cast<ptrdiff_t>(currentPosition_) + static_cast<ptrdiff_t>(len), out.begin() + static_cast<ptrdiff_t>(offset));
	currentPosition_ += len;
	return static_cast<int>(len);
}

int ByteArrayInputStream::skip(size_t n, int /*timeout*/)
{
    if (closed_)
        throw IOException("Stream is already closed.");

    const size_t originalPosition = currentPosition_;
    currentPosition_ = std::min(currentPosition_ + n, data_->size());
    return static_cast<int>(currentPosition_ - originalPosition);
}

}}} // namespace netflix::msl::io
