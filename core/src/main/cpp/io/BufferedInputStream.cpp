/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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
#include <io/BufferedInputStream.h>
#include <io/ByteArrayOutputStream.h>
#include <IOException.h>
#include <numerics/safe_math.h>
#include <algorithm>
#include <limits>

using namespace std;
using base::internal::CheckedNumeric;

namespace netflix {
namespace msl {
namespace io {

const size_t BufferedInputStream::DEFAULT_READ_SIZE = 8192;

BufferedInputStream::BufferedInputStream(shared_ptr<InputStream> source, size_t size)
    : source_(source)
    , readsize_(size)
    , buffer_(make_shared<ByteArrayOutputStream>())
{}

void BufferedInputStream::mark(size_t readlimit)
{
    // If there is data buffered and the current mark position is not
    // zero (at the beginning) then truncate the buffer.
    if (bufpos_ > 0) {
        shared_ptr<ByteArray> data = buffer_->toByteArray();
        buffer_->reset();
        buffer_->write(*data, bufpos_, data->size() - bufpos_);
        bufpos_ = 0;
    }

    // Otherwise the existing buffer contains the correct data.
    //
    // Regardless set the new read limit.
    // if input readlimit exceeds the maximum value of int this 
    // will throw an exception.
    readlimit_ = CheckedNumeric<int>(readlimit).ValueOrDie();
}

void BufferedInputStream::reset()
{
    if (readlimit_ == -1)
        throw IOException("Cannot reset before input stream has been marked or if mark has been invalidated.");

    // Start reading from the beginning of the buffer.
    bufpos_ = 0;
}

int BufferedInputStream::read(ByteArray& out, size_t offset, size_t len, int timeout)
{
    if (closed_)
        throw IOException("Stream is already closed.");

    // If we have any data in the buffer, read it first.
    ByteArray bufferedData;
    if (buffer_->size() > bufpos_) {
        // Otherwise read the amount requested but no more than
        // what remains in the buffer.
        size_t endpos = min(buffer_->size(), bufpos_ + len);

        // Extract the buffered data.
        shared_ptr<ByteArray> buffer = buffer_->toByteArray();
        bufferedData.assign(buffer->begin() + bufpos_, buffer->begin() + endpos);
        bufpos_ += bufferedData.size();

        // If the data is of sufficient size, return it.
        if (bufferedData.size() >= len) {
            copy(bufferedData.begin(), bufferedData.end(), out.begin() + offset);
            return static_cast<int>(bufferedData.size());
        }
    }

    // We were not able to read enough off the buffer.
    //
    // Read any remaining data off the backing source.
    const size_t remainingLength = len - bufferedData.size();
    const size_t readSize = max(readsize_, remainingLength);
    ByteArray sourceData(readSize);
    int count = source_->read(sourceData, timeout);

    // On end of stream, return the buffered data.
    if (count == -1) {
        copy(bufferedData.begin(), bufferedData.end(), out.begin() + offset);
        return static_cast<int>(bufferedData.size());
    }

    // Append to the buffer.
    buffer_->write(sourceData, 0, count);

    // Increment the buffer position by the amount of data we will return.
    const size_t readCount = min(static_cast<size_t>(count), remainingLength);
    bufpos_ += readCount;

    // Invalidate the mark if the requested data size exceeds the read limit.
    if (bufpos_ > static_cast<size_t>(readlimit_))
        readlimit_ = -1;

    // Return the buffered data and the read data.
    copy(bufferedData.begin(), bufferedData.end(), out.begin() + offset);
    copy(sourceData.begin(), sourceData.begin() + readCount, out.begin() + offset + bufferedData.size());
    return static_cast<int>(bufferedData.size() + readCount);
}

int BufferedInputStream::skip(size_t n, int timeout)
{
    if (closed_)
        throw IOException("Stream is already closed.");

    // If we have any data in the buffer, skip it first.
    size_t skipcount = 0;
    if (buffer_->size() > bufpos_) {
        skipcount = min(n, buffer_->size() - bufpos_);
        bufpos_ += skipcount;

        // If we skipped as much as requested return immediately.
        if (skipcount == n)
            return static_cast<int>(skipcount);
    }

    // We were not able to skip enough using just buffered data.
    ByteArray data(n - skipcount);
    int readcount = read(data, timeout);
    if (readcount == -1) return static_cast<int>(skipcount);
    return static_cast<int>(readcount + skipcount);
}

}}} // namespace netflix::msl::io
