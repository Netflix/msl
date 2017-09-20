/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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
#include <crypto/EccCryptoContext.h>
#include <MslCryptoException.h>
#include <MslError.h>
#include <crypto/Key.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderFormat.h>
#include <string>

// FIXME TODO

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::io;

namespace netflix {
namespace msl {
namespace crypto {

EccCryptoContext::EccCryptoContext(const string& /*id*/, const PrivateKey& /*privateKey*/, const PublicKey& /*publicKey*/, const EccCryptoContext::Mode& /*mode*/)
{
    // FIXME TODO
}

shared_ptr<ByteArray> EccCryptoContext::encrypt(shared_ptr<ByteArray> /*data*/, shared_ptr<MslEncoderFactory> /*encoder*/, const MslEncoderFormat& /*format*/)
{
    // FIXME TODO
    return make_shared<ByteArray>();
}

shared_ptr<ByteArray> EccCryptoContext::decrypt(shared_ptr<ByteArray> /*data*/, shared_ptr<MslEncoderFactory> /*encoder*/)
{
    // FIXME TODO
    return make_shared<ByteArray>();
}

shared_ptr<ByteArray> EccCryptoContext::wrap(std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>, const io::MslEncoderFormat&) {
    throw MslCryptoException(MslError::WRAP_NOT_SUPPORTED);
}

shared_ptr<ByteArray> EccCryptoContext::unwrap(std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>) {
    throw MslCryptoException(MslError::UNWRAP_NOT_SUPPORTED);
}

shared_ptr<ByteArray> EccCryptoContext::sign(shared_ptr<ByteArray> /*data*/, shared_ptr<MslEncoderFactory> /*encoder*/, const MslEncoderFormat& /*format*/)
{
    // FIXME TODO
    return make_shared<ByteArray>();
}

bool EccCryptoContext::verify(shared_ptr<ByteArray> /*data*/, shared_ptr<ByteArray> /*signature*/, shared_ptr<MslEncoderFactory> /*encoder*/)
{
    // FIXME TODO
    return false;
}

}}} // namespace netflix::msl:;crypto
