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

#include <io/JsonHandler.h>
#include <io/JsonMslObject.h>
#include <io/JsonMslTokenizer.h>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <iostream>
#include <sstream>

//#define DEBUG
#include <util/Debug.h>
#include <memory>

#define TIMEOUT 60000

using namespace rapidjson;
using namespace std;

namespace netflix {
namespace msl {
namespace io {

namespace {
#if DEBUG_JSON
util::Debug myCout(cout);
#else
    std::ostream os(NULL);
    util::Debug myCout(os);
#endif
}

MslStreamWrapper::Ch MslStreamWrapper::Peek() const
{
	if (cache_.size() > 0)
		return cache_[0];
	ByteArray buf(1);
	int count = stream_->read(buf, 0, 1, TIMEOUT);
	if (RAPIDJSON_LIKELY(count != -1)) {
		cache_.push_back(buf[0]);
		return buf[0];
	}
	return '\0';
}

MslStreamWrapper::Ch MslStreamWrapper::Take()
{
	if (cache_.size() > 0) {
		Ch c = cache_.front();
		cache_.erase(cache_.begin());
		++count_;
		return c;
	}
	ByteArray buf(1);
	int count = stream_->read(buf, 0, 1, TIMEOUT);
	if (RAPIDJSON_LIKELY(count != -1)) {
		++count_;
		return buf[0];
	}
	return '\0';
}

const MslStreamWrapper::Ch* MslStreamWrapper::Peek4() const
{
	int len = static_cast<int>(4 - cache_.size());
	if (len > 0) {
		ByteArray buf(static_cast<size_t>(len));
		int count = stream_->read(buf, 0, static_cast<size_t>(len), TIMEOUT);
		for (int i = 0; i < count; ++i)
			cache_.push_back(buf[static_cast<size_t>(i)]);
	}
	if (cache_.size() >= 4)
		return &cache_[0];
	return 0;
}

shared_ptr<MslObject> JsonMslTokenizer::next(int /*timeout*/)
{
    // Parse a JSON object to a DOM
    Document document;
    const int parseFlags = kParseStopWhenDoneFlag;
    try {
        if (document.ParseStream<parseFlags>(mslstreamwrapper_).HasParseError())
        {
            const ParseErrorCode e = document.GetParseError();
            if (e == kParseErrorDocumentEmpty) // no more, return empty
                return shared_ptr<MslObject>();

            // We found some other parse error.
            std::stringstream ss;
            ss << "Invalid JSON encoding: " << GetParseError_En(e);
            ss << " at offset " << document.GetErrorOffset();

            // So we don't keep seeing the same error, advance the stream
            // forward, discarding everything until we find a '{'.
            uint8_t b = mslstreamwrapper_.Peek();
            while (b && b != '{')
            {
            	mslstreamwrapper_.Take(); // discard current char
                b = mslstreamwrapper_.Peek(); // peek at next, returns null at eos
            }

            throw MslEncoderException(ss.str());
        }
    }
    catch (const MslEncoderException& e) {
        throw e;
    }
    catch (...) {
        throw MslEncoderException("Invalid JSON encoding");
    }

    StringBuffer s;
    Writer<StringBuffer> writer(s);
    document.Accept(writer);
    myCout << "### " << s.GetString() << endl;

    // We now have a well-formed DOM. Translate it to a MslObject.
    shared_ptr<MslObject> mslObject = make_shared<JsonMslObject>();
    JsonHandler handler(mslObject);
    try {
        document.Accept(handler);
    }
    catch (const Exception& e) {
        throw MslEncoderException("Error when building JsonMslObject", e);
    }
    catch (...) {
        throw MslEncoderException("Unknown error when building JsonMslObject");
    }

    myCout << "$$$ " << mslObject->toString() << endl;

    return mslObject;
}

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */
