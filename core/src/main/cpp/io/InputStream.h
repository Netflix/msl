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

#ifndef SRC_IO_INPUTSTREAM_H_
#define SRC_IO_INPUTSTREAM_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io {

/**
 * An input stream provides read capability of raw bytes.
 *
 * Timeouts are triggered if no character has been read within the timeout
 * period. A slow operation that is able to read at least one character per
 * timeout period will not trigger a timeout.
 *
 * @interface
 */
class InputStream
{
public:
	virtual ~InputStream() {}

    /**
     * Aborts any outstanding operations.
     */
    virtual void abort() = 0;

    /**
     * Closes this input stream and releases any resources associated with the
     * stream.
     *
     * @param timeout write timeout in milliseconds or -1 for no timeout.
     * @return true on success, false on timeout or abort.
     */
    virtual bool close(int timeout = -1) = 0;

    /**
     * Marks the current position in this input stream. A subsequent call to
     * the reset method repositions this stream at the last marked position so
     * that subsequent reads re-read the same bytes.
     *
     * @see #reset()
     */
    virtual void mark() = 0;

    /**
     * Repositions this stream to the position at the time the mark method was
     * last called on this input stream.
     *
     * @throws IOException if this stream has not been marked.
     * @see #mark()
     */
    virtual void reset() = 0;

    /**
     * @return true if the mark and reset operations are supported.
     */
    virtual bool markSupported() = 0;

    /**
     * <p>Reads some bytes from the input stream, which may be less than the
     * number requested. This is equivalent to a call to
     * {@link #read(ByteArray&, size_t, size_t, int)} with an offset of 0 and
     * length equal to the current size of the destination byte buffer.</p>
     *
     * <p>Unless the byte buffer length is zero, this method will block until
     * at least one byte is available or the timeout is hit. If the timeout is
     * hit then whatever bytes that have been read will be returned.</p>
     *
     * <p>If there are no more bytes available (i.e. end of stream is hit)
     * then -1 is returned. This is the only reliable indicator that no more
     * data is available.</p>
     *
     * @param out destination byte buffer.
     * @param timeout read timeout in milliseconds or -1 for no timeout.
     * @return the number of bytes read or -1 on end of stream.
     * @throws IOException if there is an error reading the data or the stream
     *         is closed.
     */
    virtual int read(ByteArray& out, int timeout = -1) = 0;

    /**
     * <p>Reads some bytes from the input stream, which may be less than the
     * number requested. If 0 is specified for the length then zero bytes are
     * returned.</p>
     *
     * <p>Unless zero bytes are requested, this method will block until at
     * least one byte is available or the timeout is hit. If the timeout is
     * hit then whatever bytes that have been read will be returned.</p>
     *
     * <p>If there are no more bytes available (i.e. end of stream is hit)
     * then -1 is returned. This is the only reliable indicator that no
     * more data is available.</p>
     *
     * @param out destination byte buffer.
     * @param len the number of bytes to read.
     * @param timeout read timeout in milliseconds or -1 for no timeout.
     * @return the number of bytes read or -1 on end of stream.
     * @throws IOException if there is an error reading the data or the stream
     *         is closed.
     */
    virtual int read(ByteArray& out, size_t offset, size_t len, int timeout = -1) = 0;
};

}}} // namespace netflix::msl::io

#endif /* SRC_IO_INPUTSTREAM_H_ */
