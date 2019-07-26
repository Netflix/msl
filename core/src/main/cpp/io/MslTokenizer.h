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

#ifndef SRC_IO_MSLTOKENIZER_H_
#define SRC_IO_MSLTOKENIZER_H_

#include <io/MslObject.h>
#include <memory>

namespace netflix {
namespace msl {
namespace io {

/**
 * <p>A {@code MslTokenizer} takes in a binary source and parses out
 * {@link MslObject} and {@link MslArray} instances.</p>
 */
class MslTokenizer
{
public:
    virtual ~MslTokenizer() {}

    /**
     * <p>Create a new tokenizer.</p>
     */
    MslTokenizer() : closed_(false), aborted_(false) {}

    /**
     * <p>Closes the tokenizer, cleaning up any resources and preventing future
     * use.</p>
     *
     * @throws MslEncoderException if there is an error closing the tokenizer.
     */
    virtual void close() { closed_ = true; }

    /**
     * <p>Aborts future reading off the tokenizer.</p>
     */
    virtual void abort() { aborted_ = true; }

    /**
     * <p>Returns true if more objects can be read from the data source. This
     * method determines that by actually trying to read the next object.</p>
     *
     * @param timeout read timeout in milliseconds or -1 for no timeout (default).
     * @return true if more objects are available from the data source, false
     *         if the tokenizer has been aborted or closed.
     * @throws MslEncoderException if the next object cannot be read or the
     *         source data at the current position is invalid.
     */
    virtual bool more(int timeout = -1);

    /**
     * <p>Return the next object (should be an instance of {@link MslObject} or
     * {@link MslArray}) from the source data.</p>
     *
     * <p>If the source data's current position cannot be parsed as an object,
     * an exception is thrown and the source data position's new position is
     * undefined. Subsequent calls to this function should not re-throw the
     * exception and instead should look for the next object. The algorithm
     * used to search for the next object, and how the position should be set
     * to do so, is up to the implementer and may depend upon the encoding.</p>
     *
     * @param timeout read timeout in milliseconds or -1 for no timeout (default).
     * @return the next object or {@code null} if there are no more.
     * @throws MslEncoderException if the next object cannot be read or the
     *         source data at the current position is invalid.
     */
    virtual std::shared_ptr<MslObject> next(int timeout = -1) = 0;

    /**
     * <p>Return the next object.</p>
     *
     * @param timeout read timeout in milliseconds or -1 for no timeout (default).
     * @return the next object or an empty object if there are no more or the
     *         tokenizer has been aborted or closed;
     * @throws MslEncoderException if the next object cannot be read or the
     *         source data at the current position is invalid.
     */
    virtual std::shared_ptr<MslObject> nextObject(int timeout = -1);

private:
    /** Closed. */
    bool closed_;
    /** Aborted. */
    bool aborted_;
    /** Cached next object. */
    std::shared_ptr<MslObject> next_;
};

}}} // namespace netflix::msl::io

#endif /* SRC_IO_MSLTOKENIZER_H_ */
