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

#ifndef SRC_IO_MSLENCODABLE_H_
#define SRC_IO_MSLENCODABLE_H_

#include <memory>
#include <stdint.h>
#include <vector>

namespace netflix {
namespace msl {
namespace io {

class MslEncoderFactory;
class MslEncoderFormat;

typedef std::vector<uint8_t> ByteArray;

/**
 * <p>This interface allows a class to override the default behavior when being
 * encoded into a {@link MslObject} or {@link MslArray}.</p>
 */
class MslEncodable
{
public:
    virtual ~MslEncodable() {}

    /**
     * Returns the requested encoding of a MSL object representing the
     * implementing class.
     *
     * @param encoder the encoder factory.
     * @param format the encoder format.
     * @return a MSL encoding of the MSL object.
     * @throws MslEncoderException if the encoder format is not supported or
     *         there is an error encoding the data.
     */
    virtual std::shared_ptr<ByteArray> toMslEncoding(std::shared_ptr<MslEncoderFactory> encoder, const MslEncoderFormat& format) const = 0;
};

}}} // namespace netflix::msl::io

#endif /* SRC_IO_MSLENCODABLE_H_ */
