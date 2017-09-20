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

#ifndef SRC_IO_OUTPUTSTREAM_H_
#define SRC_IO_OUTPUTSTREAM_H_

#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io {

/**
 * An output stream provides write capability of raw bytes.
 *
 * Timeouts are triggered if no character has been sent within the timeout
 * period. A slow operation that is able to write at least one character per
 * timeout period will not trigger a timeout.
 *
 * @interface
 */
class OutputStream
{
public:
	virtual ~OutputStream() {}

    /**
     * Abort any outstanding operations.
     */
    virtual void abort() = 0;

    /**
     * Closes this output stream and releases any resources associated with the
     * stream.
     *
     * @param timeout write timeout in milliseconds.
     * @return true on success, false on timeout or abort.
     * @throws IOException if there is an error closing the stream.
     */
    virtual bool close() = 0;

    /**
     * Writes the byte array to the output stream. This is equivalent to a call
     * to {@link #write(const ByteArray&, size_t, size_t, int)} with an offset
     * of 0 and length equal to the current size of the data.
     *
     * @param data the data to write.
     * @param timeout write timeout in milliseconds or -1 for no timeout.
     * @return the number of bytes written which will be less than the length
     *         on timeout or abort.
     * @throws IOException if there is an error writing the data or the stream
     *         is closed.
     */
    virtual size_t write(const ByteArray& data, int timeout = -1) = 0;

    /**
     * Writes the specified portion of the byte array to the output stream.
     *
     * @param data the data to write.
     * @param off offset into the data.
     * @param len number of bytes to write.
     * @param timeout write timeout in milliseconds or -1 for no timeout.
     * @return the number of bytes written which will be less than the length
     *         on timeout or abort.
     * @throws IOException if there is an error writing the data or the stream
     *         is closed.
     * @throws IllegalArgumentException if the offset is negative, the length
     *         is negative, or the offset plus length exceeds the data length.
     */
    virtual size_t write(const ByteArray& data, size_t off, size_t len, int timeout = -1) = 0;

    /**
     * Flushes this output stream so any buffered data is written out.
     *
     * @param timeout write timeout in milliseconds or -1 for no timeout.
     * @param true on success, false on timeout or abort.
     * @throws IOException if there is an error flushing the data.
     */
    virtual bool flush(int timeout = -1) = 0;
};

}}} // namespace netflix::msl::io

#endif /* SRC_IO_OUTPUTSTREAM_H_ */
