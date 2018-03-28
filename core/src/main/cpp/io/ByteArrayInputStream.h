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

#ifndef SRC_IO_BYTEARRAYINPUTSTREAM_H_
#define SRC_IO_BYTEARRAYINPUTSTREAM_H_

#include <io/InputStream.h>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace io {

/**
 * Reads data from a byte array.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class ByteArrayInputStream : public InputStream
{
public:
	/** Destructor. */
	virtual ~ByteArrayInputStream() { close(); }

    /**
     * Create a new byte array input stream from the provided data.
     *
     * @param data the data.
     */
	ByteArrayInputStream(std::shared_ptr<ByteArray> data)
		: data_(data)
		, closed_(false)
		, currentPosition_(0)
		, mark_(0)
	{}

	/**
	 * Create a new byte array input stream from the provided string.
	 *
	 * @param s the string.
	 */
	ByteArrayInputStream(const std::string& s)
		: data_(std::make_shared<ByteArray>(s.begin(), s.end()))
		, closed_(false)
		, currentPosition_(0)
		, mark_(0)
	{}

    /** @inheritDoc */
    virtual void abort() {};

    /** @inheritDoc */
    virtual bool close(int timeout = -1);

    /** @inheritDoc */
    virtual void mark(size_t readlimit);

    /** @inheritDoc */
    virtual void reset();

    /** @inheritDoc */
    virtual bool markSupported() { return true; }

    /** @inheritDoc */
    virtual int read(ByteArray& out, int timeout = -1) { return read(out, 0, out.size(), timeout); }

    /** @inheritDoc */
    virtual int read(ByteArray& out, size_t offset, size_t len, int timeout = -1);

    /** @inheritDoc */
    virtual int skip(size_t n, int timeout = -1);

protected:
	/** Backing data. */
	std::shared_ptr<ByteArray> data_;
	/** Closed. */
	bool closed_;
	/** Current position. */
	size_t currentPosition_;
	/** Mark location. */
	size_t mark_;
};

}}} // namespace netflix::msl::io

#endif /* SRC_IO_BYTEARRAYINPUTSTREAM_H_ */
