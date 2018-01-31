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

#include <crypto/Key.h>
#include <IllegalArgumentException.h>

using namespace std;

namespace netflix {
namespace msl {
namespace crypto {

Key::Key(shared_ptr<ByteArray> key, const std::string& algorithm, const std::string& format)
    : isNull_(false), key_(key), algorithm_(algorithm), format_(format)
{
    if (!key || key->empty())
        throw IllegalArgumentException("empty key data");
}

Key::Key(const Key& other)
    : isNull_(other.isNull_)
    , key_(other.key_)
    , algorithm_(other.algorithm_)
    , format_(other.format_)
{
}

Key Key::operator=(const Key& rhs)
{
    isNull_ = rhs.isNull_;
    key_ = rhs.key_;
    algorithm_ = rhs.algorithm_;
    format_ = rhs.format_;
    return *this;
}

bool operator==(const IKey& a, const IKey& b)
{
    if (a.isNull() && b.isNull())
        return true;
    if (a.isNull() || b.isNull())
    	return false;
    if ( (*a.getEncoded() == *b.getEncoded()) && (a.getAlgorithm() == b.getAlgorithm()) )
        return true;
    return false;
}

const char *SecretKey::DEFAULT_FORMAT = "RAW";
const char *PrivateKey::DEFAULT_FORMAT = "PKCS8";
const char *PublicKey::DEFAULT_FORMAT = "SPKI";

}}} // namespace netflix::msl::crypto
