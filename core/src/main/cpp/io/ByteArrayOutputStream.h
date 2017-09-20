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

#ifndef SRC_IO_BYTEARRAYOUTPUTSTREAM_H_
#define SRC_IO_BYTEARRAYOUTPUTSTREAM_H_

#include <io/OutputStream.h>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io {

/**
 * Accumulates all received data into a byte array.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class ByteArrayOutputStream : public OutputStream
{
public:
	/** Destructor. */
	virtual ~ByteArrayOutputStream() { close(); }

    /**
     * Create a new byte array output stream.
     */
    ByteArrayOutputStream() {}

	/** @inheritDoc */
	virtual void abort() {}

    /** @inheritDoc */
    virtual bool close();

    /** @inheritDoc */
    virtual size_t write(const ByteArray& data, int timeout = -1) { return write(data, 0, data.size(), timeout); }

    /** @inheritDoc */
    virtual size_t write(const ByteArray& data, size_t off, size_t len, int timeout = -1);

    /** @inheritDoc */
    virtual bool flush(int timeout = -1);

    /**
    * @return {number} the number of accumulated bytes.
    */
    virtual size_t size() { return result_->size(); }

    /**
     * Resets the output stream and clears out all accumulated data.
     */
    virtual void reset() { result_->clear(); }

	/**
	 * @return {Uint8Array} a Uint8Array of the accumulated bytes.
	 */
	virtual std::shared_ptr<ByteArray> toByteArray();

private:
    /** Closed. */
	bool closed_ = false;
	/** Flushed data buffer. */
	std::shared_ptr<ByteArray> result_ = std::make_shared<ByteArray>();
};

}}} // namespace netflix::msl::io

#endif /* SRC_IO_BYTEARRAYOUTPUTSTREAM_H_ */
