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
#ifndef SRC_IO_BUFFEREDINPUTSTREAM_H_
#define SRC_IO_BUFFEREDINPUTSTREAM_H_

#include <io/InputStream.h>

#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io {
class ByteArrayOutputStream;

/**
 * <p>A {@code BufferedInputStream} adds support for the {@code mark()} and
 * {@code reset()} functions.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class BufferedInputStream : public InputStream
{
public:
    /** Default read size: 8192 bytes. */
    static const size_t DEFAULT_READ_SIZE;

    virtual ~BufferedInputStream() {}

    /**
     * Create a new buffered input stream that will read from the provided
     * source input stream in byte chunks of the specified size.
     *
     * @param source the source input stream.
     * @param size read size.
     */
    BufferedInputStream(std::shared_ptr<InputStream> source, size_t size = DEFAULT_READ_SIZE);

    /** @inheritDoc */
    virtual void abort()
    {
        source_->abort();
    }

    /** @inheritDoc */
    virtual bool close(int timeout = -1)
    {
        closed_ = true;
        return source_->close(timeout);
    }

    /** @inheritDoc */
    virtual void mark(size_t readlimit);

    /** @inheritDoc */
    virtual void reset();

    /** @inheritDoc */
    virtual bool markSupported() { return true; }

    /** @inheritDoc */
    virtual int read(ByteArray& out, int timeout = -1)
    {
        return read(out, 0, out.size(), timeout);
    }

    /** @inheritDoc */
    virtual int read(ByteArray& out, size_t offset, size_t len, int timeout = -1);

    /** @inheritDoc */
    virtual int skip(size_t n, int timeout = -1);

private:
    /** The backing input stream. */
    std::shared_ptr<InputStream> source_;
    /** Read size in bytes. */
    size_t readsize_;
    /**
     * Buffer of data read since the last call to mark(). Not set if
     * mark() has not been called or if the read limit has been
     * exceeded.
     */
    std::shared_ptr<ByteArrayOutputStream> buffer_;
    /** Current buffer read position. */
    size_t bufpos_ = 0;
    /**
     * Requested maximum number of bytes before the mark is invalidated. Will
     * be -1 if the mark is not active.
     */
    int readlimit_ = -1;
    /** True if stream is closed. */
    bool closed_ = false;
};

}}} // namespace netflix::msl::io
#endif /* SRC_IO_BUFFEREDINPUTSTREAM_H_ */
