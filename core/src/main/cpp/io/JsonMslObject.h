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

#ifndef SRC_IO_JSONMSLOBJECT_H_
#define SRC_IO_JSONMSLOBJECT_H_

#include <io/MslObject.h>
#include <memory>

namespace netflix {
namespace msl {

typedef std::vector<uint8_t> ByteArray;

namespace io {

class MslEncoderFactory;

class JsonMslObject : public MslObject
{
public:
    virtual ~JsonMslObject() {}

    /**
     * Create an empty {@code JsonMslObject}.
     */
    JsonMslObject();

    /**
     * Create a {@code JsonMslObject} from the given {@code MslObject}.
     *
     * @param o the {@code MslObject}.
     * @throws MslEncoderException if the MSL object contains an unsupported
     *         type.
     */
    JsonMslObject(std::shared_ptr<MslObject> o);

    /**
     * Create a new {@code JsonMslObject} from its encoded representation.
     *
     * @param encoding the encoded data.
     * @throws MslEncoderException if the data is malformed or invalid.
     */
    JsonMslObject(std::shared_ptr<ByteArray> encoding);

    /** @inheritDoc */
    virtual void put(const std::string& key, const Variant& value);
    template <typename T> void put(const std::string& key, const T& value);

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> getBytes(const std::string& key) const;

    /** @inheritDoc */
    virtual int64_t getLong(const std::string& key) const;

    /** @inheritDoc */
    virtual double getDouble(const std::string& key) const;

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> optBytes(const std::string& key, std::shared_ptr<ByteArray> defaultValue = std::make_shared<ByteArray>()) const;

    /** @inheritDoc */
    virtual int64_t optLong(const std::string& key, int64_t defaultValue = 0) const;

    /** @inheritDoc */
    virtual double optDouble(const std::string& key, double defaultValue = std::numeric_limits<double>::quiet_NaN()) const;

    /**
     * Return a JSON representation of this instance.
     */
    std::string toJsonString(std::shared_ptr<MslEncoderFactory> encoder) const;

    /** @inheritDoc */
    virtual std::string toString() const;

    /**
     * Returns a JSON MSL encoding of provided MSL object.
     *
     * @param encoder the encoder factory.
     * @param object the MSL object.
     * @return the encoded data.
     * @throws MslEncoderException if there is an error encoding the data.
     */
    static std::shared_ptr<ByteArray> getEncoded(std::shared_ptr<MslEncoderFactory> encoder, std::shared_ptr<MslObject> object);
};

template <typename T>
void JsonMslObject::put(const std::string& key, const T& value)
{
    STATIC_ASSERT(isAllowed<T>::value);
    put(key, VariantFactory::create<T>(value));
}

}}} // namespace netflix::msl::io

#endif /* SRC_IO_JSONMSLOBJECT_H_ */
