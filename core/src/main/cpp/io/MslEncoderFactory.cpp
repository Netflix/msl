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

#include <io/InputStream.h>
#include <io/BufferedInputStream.h>
#include <io/MslArray.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <io/MslObject.h>

#include <iomanip>
#include <iosfwd>
#include <sstream>

#define TIMEOUT 60000

using namespace std;

namespace netflix {
namespace msl {
namespace io {

//static
string MslEncoderFactory::quote(const std::string& string)
{
    ostringstream oss;

    // Return "" zero-length string.
    if (string.length() == 0) {
        oss << "\"\"";
        return oss.str();
    }

    oss << '"';
    char c = 0;
    for (string::const_iterator it = string.begin(); it != string.end(); ++it)
    {
        const char b = c;
        c = *it;
        switch (c) {
            case '\\':
            case '"':
                oss << '\\';
                oss << c;
                break;
            case '/':
                if (b == '<') {
                    oss << '\\';
                }
                oss << c;
                break;
            case '\b':
                oss << "\\b";
                break;
            case '\t':
                oss << "\\t";
                break;
            case '\n':
                oss << "\\n";
                break;
            case '\f':
                oss << "\\f";
                break;
            case '\r':
                oss << "\\r";
                break;
            default:
                // FIXME
//                if (c < ' ' || (c >= '\x80' && c < '\xa0')) {
//                   // || (c >= '\u2000' && c < '\u2100'))  FIXME??
//                    oss << "\\u" << setfill('0') << setw(4) << hex << c;
//                } else {
                    oss << c;
//                }
        }
    }
    oss << '"';
    return oss.str();
}

//static
string MslEncoderFactory::stringify(const Variant& value)
{
    if (value.isType<MslObject>()) {
        return stringify(value.get<shared_ptr<MslObject>>());
    } else if (value.isType<MslArray>()) {
        return stringify(value.get<shared_ptr<MslArray>>());
    } else {
        return value.toString();
    }
}

MslEncoderFormat MslEncoderFactory::parseFormat(shared_ptr<ByteArray> encoding)
{
    // Fail if the encoding is too short.
    if (encoding->size() < 1)
        throw MslEncoderException("No encoding identifier found.");

    // Identify the encoder format.
    const uint8_t id = (*encoding)[0];
    const MslEncoderFormat format = MslEncoderFormat::getFormat(id);
    if (format == MslEncoderFormat::INVALID) {
        stringstream ss;
        ss << "Unidentified encoder format ID: (byte)0x" << hex << static_cast<unsigned>(id) << ".";
        throw MslEncoderException(ss.str());
    }
    return format;
}

shared_ptr<MslTokenizer> MslEncoderFactory::createTokenizer(shared_ptr<InputStream> source)
{
    // Read the byte stream identifier (and only the identifier).
    shared_ptr<InputStream> bufferedSource = source->markSupported() ? source : make_shared<BufferedInputStream>(source, 1);
    const int WIDTH = 1;
    ByteArray buffer(WIDTH);
    bufferedSource->mark(1);
    const int count = bufferedSource->read(buffer, 0, WIDTH, TIMEOUT); // TODO: Someone has to tell me this timeout.
    if (count == -1)
        throw new MslEncoderException("End of stream reached when attempting to read the byte stream identifier.");
    if (count == 0)
        throw new MslEncoderException("Timeout when attempting to read the byte stream identifier.");

    // Identify the encoder format.
    const uint8_t id = buffer[0];
    const MslEncoderFormat format = MslEncoderFormat::getFormat(id);
    if (format == MslEncoderFormat::INVALID) {
        stringstream ss;
        ss << "Unidentified encoder format ID: (byte)0x" << hex << static_cast<unsigned>(id) << ".";
        throw MslEncoderException(ss.str());
    }

    // Reset the input stream and return the tokenizer.
    bufferedSource->reset();
    return generateTokenizer(bufferedSource, format);
}

}}} // namespace netflix::msl::io
