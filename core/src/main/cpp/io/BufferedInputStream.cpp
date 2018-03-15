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

#include <algorithm>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

void BufferedInputStream::mark(size_t readlimit)
{
    // If there is no current mark, then start buffering.
    if (!buffer_) {
        buffer_ = make_shared<ByteArrayOutputStream>();
        bufpos_ = 0;
        readlimit_ = readlimit;
        return;
    }

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
    // Set the new read limit.
    readlimit_ = readlimit;
}

void BufferedInputStream::reset()
{
    if (!buffer_)
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
    if (buffer_ && buffer_->size() > bufpos_) {
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
            return bufferedData.size();
        }
    }

    // We were not able to read enough off the buffer.
    //
    // Read any remaining data off the backing source.
    const size_t remainingLength = len - bufferedData.size();
    ByteArray sourceData(remainingLength);
    int count = source_->read(sourceData, timeout);

    // On end of stream, return the buffered data.
    if (count == -1) {
        copy(bufferedData.begin(), bufferedData.end(), out.begin() + offset);
        return bufferedData.size();
    }

    // Append to the buffer if we are buffering.
    if (buffer_) {
        // Stop buffering if the additional data would exceed the read limit.
        if (buffer_->size() + count > readlimit_) {
            buffer_.reset();
            bufpos_ = 0;
            readlimit_ = 0;
        }

        // Otherwise append.
        else {
            buffer_->write(sourceData, 0, count);
            bufpos_ += count;
            // The mark position should now be equal to the buffer length.
        }
    }

    // Return the buffered data and the read data.
    copy(bufferedData.begin(), bufferedData.end(), out.begin() + offset);
    copy(sourceData.begin(), sourceData.begin() + count, out.begin() + offset);
    return bufferedData.size() + count;
}

int BufferedInputStream::skip(size_t n, int timeout)
{
    if (closed_)
        throw IOException("Stream is already closed.");

    // If we have any data in the buffer, skip it first.
    size_t skipcount = 0;
    if (buffer_ && buffer_->size() > bufpos_) {
        skipcount = min(n, buffer_->size() - bufpos_);
        bufpos_ += skipcount;

        // If we skipped as much as requested return immediately.
        if (skipcount == n)
            return skipcount;
    }

    // We were not able to skip enough using just buffered data.
    ByteArray data(n - skipcount);
    int readcount = read(data, timeout);
    if (readcount == -1) return skipcount;
    return readcount + skipcount;
}

}}} // namespace netflix::msl::io
