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

#ifndef SRC_IO_JSONMSLARRAY_H_
#define SRC_IO_JSONMSLARRAY_H_

#include <io/MslArray.h>

namespace netflix {
namespace msl {
namespace io {

class MslEncoderFactory;

class JsonMslArray: public MslArray
{
public:
    virtual ~JsonMslArray() {}

    /**
     * Create an empty {@code JsonMslArray}.
     */
    JsonMslArray();

    /**
     * Create a {@code JsonMslArray} from the given {@code MslArray}.
     *
     * @param a the {@code MslArray}.
     * @throws MslEncoderException if the MSL array contains an unsupported
     *         type.
     */
    JsonMslArray(std::shared_ptr<MslArray> a);

    /**
     * Create a new {@code JsonMslArray} from its encoded representation.
     *
     * @param encoding the encoded data.
     * @throws MslEncoderException if the data is malformed or invalid.
     */
    JsonMslArray(std::shared_ptr<ByteArray> encoding);

    /** @inheritDoc */
    virtual void put(int index, const Variant& value);
    template <typename T> void put(int index, const T& value);

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> getBytes(int index) const;

    /** @inheritDoc */
    virtual int64_t getLong(int index) const;

    /** @inheritDoc */
    virtual double getDouble(int index) const;

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> optBytes(int index, std::shared_ptr<ByteArray> defaultValue = std::make_shared<ByteArray>()) const;

    /** @inheritDoc */
    virtual int64_t optLong(int index, int64_t defaultValue = 0) const;

    /** @inheritDoc */
    virtual double optDouble(int index, double defaultValue = std::numeric_limits<double>::quiet_NaN()) const;

    /**
     * Return a JSON representation of this instance.
     */
    std::string toJsonString(std::shared_ptr<MslEncoderFactory> encoder) const;

    /** @inheritDoc */
    virtual std::string toString() const;
};

template <typename T>
void JsonMslArray::put(int index, const T& value) {
	STATIC_ASSERT(isAllowed<T>::value);
	put(index, VariantFactory::create<T>(value));
}

}}} // netflix::msl::io

#endif /* SRC_IO_JSONMSLARRAY_H_ */
