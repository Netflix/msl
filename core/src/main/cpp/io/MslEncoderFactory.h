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

#ifndef SRC_IO_MSLENCODERFACTORY_H_
#define SRC_IO_MSLENCODERFACTORY_H_

#include <io/MslArray.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>
#include <io/MslTokenizer.h>
#include <memory>
#include <string>
#include <vector>

namespace netflix {
namespace msl {
namespace io {

class InputStream;
class Variant;

/**
 * <p>An abstract factory class for producing {@link MslTokenizer},
 * {@link MslObject}, and {@link MslArray} instances of various encoder
 * formats.</p>
 *
 * <p>A concrete implementations must identify its supported and preferred
 * encoder formats and provide implementations for encoding and decoding those
 * formats.</p>
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MslEncoderFactory : public std::enable_shared_from_this<MslEncoderFactory>
{
public:
    virtual ~MslEncoderFactory() {}
    MslEncoderFactory() {}

    /**
     * <p>Escape and quote a string for print purposes.</p>
     *
     * @param string the string to quote. May be empty.
     * @return the quoted string.
     */
    static std::string quote(const std::string& string);

    /**
     * <p>Convert a value to a string for print purposes.</p>
     *
     * @param value the value to convert to a string. May be {@code null}.
     * @return the string.
     */
    static std::string stringify(const Variant& value);
    static std::string stringify(std::shared_ptr<MslObject> value) {return value->toString();}
    static std::string stringify(std::shared_ptr<MslArray> value) {return value->toString();}

    /**
     * Returns the most preferred encoder format from the provided set of
     * formats.
     *
     * @param formats the set of formats to choose from. May be missing or
     *        empty.
     * @return the preferred format from the provided set or the default format
     *         if format set is missing or empty.
     */
    virtual MslEncoderFormat getPreferredFormat(const std::set<MslEncoderFormat>& formats = std::set<MslEncoderFormat>()) = 0;

    /**
     * Create a new {@link MslTokenizer}. The encoder format will be
     * determined by inspecting the byte stream identifier located in the first
     * byte.
     *
     * @param source the binary data to tokenize.
     * @return the {@link MslTokenizer}.
     * @throws IOException if there is a problem reading the byte stream
     *         identifier.
     * @throws MslEncoderException if the encoder format is not recognized or
     *         is not supported.
     */
    std::shared_ptr<MslTokenizer> createTokenizer(std::shared_ptr<InputStream> source);

protected:
    /**
     * Create a new {@link MslTokenizer} of the specified encoder format.
     *
     * @param source the binary data to tokenize.
     * @param format the encoder format.
     * @return the {@link MslTokenizer}.
     * @throws MslEncoderException if the encoder format is not supported.
     */
    virtual std::shared_ptr<MslTokenizer> generateTokenizer(std::shared_ptr<InputStream> source, const MslEncoderFormat& format) = 0;

public:
    /**
     * Create a new {@link MslObject} populated with the provided map.
     *
     * @param map the map of name/value pairs. This must be a map of
     *        {@code String}s onto {@code Variant}s. May be empty.
     * @return the {@link MslObject}.
     */
    std::shared_ptr<MslObject> createObject(const std::map<std::string, Variant> map = std::map<std::string, Variant>()) {
        return std::make_shared<MslObject>(map);
    }

    /**
     * Identify the encoder format of the {@link MslObject} of the encoded
     * data. The format will be identified by inspecting the byte stream
     * identifier located in the first byte.
     *
     * @param encoding the encoded data.
     * @return the encoder format.
     * @throws MslEncoderException if the encoder format cannot be identified
     *         or there is an error parsing the encoder format ID.
     */
    MslEncoderFormat parseFormat(std::shared_ptr<ByteArray> encoding);

    /**
     * Parse a {@link MslObject} from encoded data. The encoder format will be
     * determined by inspecting the byte stream identifier located in the first
     * byte.
     *
     * @param encoding the encoded data to parse.
     * @return the {@link MslObject}.
     * @throws MslEncoderException if the encoder format is not supported or
     *         there is an error parsing the encoded data.
     */
    virtual std::shared_ptr<MslObject> parseObject(std::shared_ptr<ByteArray> encoding) = 0;

    /**
     * Encode a {@link MslObject} into the specified encoder format.
     *
     * @param object the {@link MslObject} to encode.
     * @param format the encoder format.
     * @return the encoded data.
     * @throws MslEncoderException if the encoder format is not supported or
     *         there is an error encoding the object.
     */
    virtual std::shared_ptr<ByteArray> encodeObject(std::shared_ptr<MslObject> object, const MslEncoderFormat& format) = 0;

    /**
     * Create a new {@link MslArray} populated with the provided list.
     *
     * @param vector of {@code Variant}s. May be empty.
     * @return the {@link MslObject}.
     */
    std::shared_ptr<MslArray> createArray(const std::vector<Variant> list = std::vector<Variant>())
    {
        return std::make_shared<MslArray>(list);
    }
};

} /* namespace io */
} /* namespace msl */
} /* namespace netflix */

#endif /* SRC_IO_MSLENCODERFACTORY_H_ */

