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

#ifndef SRC_IO_JSONMSLTOKENIZER_H_
#define SRC_IO_JSONMSLTOKENIZER_H_

#include <Macros.h>
#include <io/InputStream.h>
#include <io/MslTokenizer.h>
#include <rapidjson/stream.h>
#include <cassert>
#include <istream>
#include <memory>
#include <vector>

namespace netflix {
namespace msl {
namespace io {

class MslStreamWrapper
{
public:
	// rapidjson requires a Ch definition.
	typedef uint8_t Ch;

	MslStreamWrapper(std::shared_ptr<netflix::msl::io::InputStream> stream)
		: stream_(stream)
		, count_(0)
	{}

	Ch Peek() const ;

	Ch Take();

	size_t Tell() const { return count_; }

	// Writing is not permitted.
	Ch* PutBegin() { assert(false); return 0; }
    void Put(Ch) { assert(false); }
    void Flush() { assert(false); }
    size_t PutEnd(Ch*) { assert(false); return 0; }

    // For encoding detection only.
    const Ch* Peek4() const;
private:
	/** Input stream. */
	std::shared_ptr<netflix::msl::io::InputStream> stream_;
	/** Number of characters read. */
	size_t count_;
	/** Cached bytes. */
	mutable std::vector<uint8_t> cache_;
};

class JsonMslTokenizer : public MslTokenizer
{
public:
    virtual ~JsonMslTokenizer() {}

    /**
     * <p>Create a new JSON MSL tokenzier that will read data off the provided
     * input stream.</p>
     *
     * @param encoder MSL encoder factory.
     * @param source JSON input stream.
     */
    JsonMslTokenizer(std::shared_ptr<InputStream> stream) : mslstreamwrapper_(stream) {}

    /** @inheritDoc */
    virtual std::shared_ptr<MslObject> next(int timeout = -1);
private:
    /** JSON stream. */
    MslStreamWrapper mslstreamwrapper_;
    DISALLOW_COPY_AND_ASSIGN(JsonMslTokenizer);
};

}}} // namespace netflix::msl::io

#endif /* SRC_IO_JSONMSLTOKENIZER_H_ */
