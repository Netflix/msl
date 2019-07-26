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

#ifndef SRC_CRYPTO_CLIENTMSLCRYPTOCONTEXT_H_
#define SRC_CRYPTO_CLIENTMSLCRYPTOCONTEXT_H_

#include <crypto/ICryptoContext.h>
#include <MslInternalException.h>

namespace netflix {
namespace msl {
namespace crypto {

class ClientMslCryptoContext: public crypto::ICryptoContext
{
public:
    virtual ~ClientMslCryptoContext() {}
    ClientMslCryptoContext() {}

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> encrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory>, const io::MslEncoderFormat&)
    {
        return data;
    }

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> decrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory>)
    {
        return data;
    }

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> wrap(std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>, const io::MslEncoderFormat&)
    {
        // This should never be called.
        throw MslInternalException("Wrap is unsupported by the MSL client crypto context.");
    }

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> unwrap(std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>)
    {
        // This should never be called.
        throw MslInternalException("Unwrap is unsupported by the MSL client crypto context.");
    }

    /** @inheritDoc */
    virtual std::shared_ptr<ByteArray> sign(std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>, const io::MslEncoderFormat&)
    {
        return std::make_shared<ByteArray>();
    }

    /** @inheritDoc */
    virtual bool verify(std::shared_ptr<ByteArray>, std::shared_ptr<ByteArray>, std::shared_ptr<io::MslEncoderFactory>)
    {
        return false;
    }
};

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_CLIENTMSLCRYPTOCONTEXT_H_ */
