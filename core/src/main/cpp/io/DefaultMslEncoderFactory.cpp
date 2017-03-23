/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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

#include <io/DefaultMslEncoderFactory.h>
#include <io/JsonMslObject.h>
#include <io/JsonMslTokenizer.h>
#include <io/MslEncoderException.h>
#include <io/MslEncoderFormat.h>
#include <memory>
#include <set>
#include <sstream>
#include <string>

using namespace std;

namespace netflix {
namespace msl {
namespace io {

MslEncoderFormat DefaultMslEncoderFactory::getPreferredFormat(const set<MslEncoderFormat>&)
{
    // We don't know about any other formats right now.
    return MslEncoderFormat::JSON;
}

shared_ptr<MslTokenizer> DefaultMslEncoderFactory::generateTokenizer(shared_ptr<InputStream> source, const MslEncoderFormat& format)
{
    // JSON.
    if (format == MslEncoderFormat::JSON)
        return make_shared<JsonMslTokenizer>(source);

    // Unsupported encoder format.
    stringstream ss;
    ss << "Unsupported encoder format: " << format << ".";
    throw MslEncoderException(ss.str());
}

shared_ptr<MslObject> DefaultMslEncoderFactory::parseObject(shared_ptr<ByteArray> encoding)
{
    // Identify the encoder format.
    const MslEncoderFormat format = parseFormat(encoding);

    // JSON.
    if (format == MslEncoderFormat::JSON)
        return make_shared<JsonMslObject>(encoding);

    // Unsupported encoder format.
    stringstream ss;
    ss << "Unsupported encoder format: " << format << ".";
    throw MslEncoderException(ss.str());
}

shared_ptr<ByteArray> DefaultMslEncoderFactory::encodeObject(shared_ptr<MslObject> object, const MslEncoderFormat& format)
{
    // JSON.
    if (format == MslEncoderFormat::JSON)
    	return JsonMslObject::getEncoded(shared_from_this(), object);

    // Unsupported encoder format.
    stringstream ss;
    ss << "Unsupported encoder format: " << format << ".";
    throw MslEncoderException(ss.str());
}

}}} // namespace netflix::msl::io
