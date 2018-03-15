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

#include <msg/ConsoleFilterStreamFactory.h>
#include <io/InputStream.h>
#include <io/OutputStream.h>
#include <RangeException.h>
#include <iostream>
#include <sstream>

using namespace std;
using namespace netflix::msl::io;

namespace netflix {
namespace msl {
namespace msg {

namespace {
/**
 * A filter input stream that outputs read data to stdout. A new line is
 * output when the stream is closed.
 */
class ConsoleInputStream : public InputStream
{
public:
	/** Destructor. */
	virtual ~ConsoleInputStream() { close(); }

    /**
     * Create a new console input stream backed by the provided input
     * stream.
     *
     * @param in the backing input stream.
     */
	ConsoleInputStream(shared_ptr<InputStream> in) : in_(in) {}

	/** @inheritDoc */
	virtual void abort() {}

	/** @inheritDoc */
	virtual bool close(int timeout = -1) {
		cout << endl;
		cout.flush();
		return in_->close(timeout);
	}

	/** @inheritDoc */
	virtual void mark(size_t readlimit) {
		in_->mark(readlimit);
	}

	/** @inheritDoc */
	virtual void reset() {
		in_->reset();
	}

	/** @inheritDoc */
	virtual bool markSupported() {
		return in_->markSupported();
	}

    /** @inheritDoc */
    virtual int read(ByteArray& out, int timeout = -1) {
        return read(out, 0, out.size(), timeout);
    }

    /** @inheritDoc */
    virtual int read(ByteArray& out, size_t offset, size_t len, int timeout) {
        int r = in_->read(out, offset, len, timeout);
        if (r > 0) {
            cout.write(reinterpret_cast<const char*>(&out[0]), r);
            cout.flush();
        }
        return r;
    }

    /** @inheritDoc */
    virtual int skip(size_t n, int timeout = -1) {
        return in_->skip(n, timeout);
    }

private:
    /** Backing input stream. */
    shared_ptr<InputStream> in_;
};

/**
 * A filter output stream that outputs written data to stdout. A newline is
 * output when the stream is closed.
 */
class ConsoleOutputStream : public OutputStream
{
public:
	/** Destructor. */
	virtual ~ConsoleOutputStream() { close(); }

    /**
     * Create a new console output stream backed by the provided output
     * stream.
     *
     * @param out the backing output stream.
     */
    ConsoleOutputStream(shared_ptr<OutputStream> out) : out_(out) {}

    /** @inheritDoc */
    virtual void abort() {}

    /** @inheritDoc */
    virtual bool close() {
        cout << endl;
        cout.flush();
        return out_->close();
    }

    /** @inheritDoc */
    virtual size_t write(const ByteArray& data, int timeout = -1) { return write(data, 0, data.size(), timeout); }

    /** @inheritDoc */
    virtual size_t write(const ByteArray& data, size_t off, size_t len, int timeout) {
        if (off + len > data.size()) {
            stringstream ss;
            ss << "offset " << off << " plus length " << len << " exceeds data size " << data.size();
            throw RangeException(ss.str());
        }
        cout.write(reinterpret_cast<const char*>(&data[off]), static_cast<streamsize>(len));
        cout.flush();
        return out_->write(data, off, len, timeout);
    }

    /** @inheritDoc */
    virtual bool flush(int timeout) {
        return out_->flush(timeout);
    }

private:
    /** Backing output stream. */
    shared_ptr<OutputStream> out_;
};

} // namespace anonymous

shared_ptr<InputStream> ConsoleFilterStreamFactory::getInputStream(shared_ptr<InputStream> in) {
	return make_shared<ConsoleInputStream>(in);
}

shared_ptr<OutputStream> ConsoleFilterStreamFactory::getOutputStream(shared_ptr<OutputStream> out) {
	return make_shared<ConsoleOutputStream>(out);
}

}}} // namespace netflix::msl::msg
