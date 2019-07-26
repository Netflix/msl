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

#include <assert.h>
#include <util/Hex.h>
#include <iomanip>
#include <sstream>

using namespace std;

namespace netflix {
namespace msl {
namespace util {

shared_ptr<ByteArray> fromHex(const string &in)
{
    size_t length = in.length();
    assert(!(length & 1u));  // must be even
    shared_ptr<ByteArray> out = make_shared<ByteArray>();
    size_t strIndex = 0;
    while (strIndex < length)
    {
        stringstream ss({in[strIndex++], in[strIndex++], 0});
        int tmpValue;
        ss >> hex >> tmpValue;
        out->push_back(static_cast<uint8_t>(tmpValue));
    }
    return out;
}

string toHex(shared_ptr<ByteArray> in)
{
    stringstream   hexStringStream;
    hexStringStream << hex << setfill('0');
    for(size_t index = 0; index < in->size(); ++index)
        hexStringStream << setw(2) << static_cast<int>((*in)[index]);
    return hexStringStream.str();
}

}}} // namespace netflix::msl::util
