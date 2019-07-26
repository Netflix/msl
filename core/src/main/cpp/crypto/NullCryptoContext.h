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

#ifndef SRC_CRYPTO_NULLCRYPTOCONTEXT_H_
#define SRC_CRYPTO_NULLCRYPTOCONTEXT_H_

#include <crypto/ICryptoContext.h>

namespace netflix
{
namespace msl
{
namespace crypto
{

/**
 * A crypto context where encryption/decryption are no-ops, signatures are
 * empty, and verification always returns true.
 */
class NullCryptoContext: public ICryptoContext
{
public:
    NullCryptoContext() {}
    virtual ~NullCryptoContext() {}

    virtual std::shared_ptr<ByteArray> encrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory>,
            const io::MslEncoderFormat&)
    {
        return data;
    }

    virtual std::shared_ptr<ByteArray> decrypt(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory>)
    {
    	return data;
    }

    virtual std::shared_ptr<ByteArray> wrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory>,
            const io::MslEncoderFormat&)
    {
        return data;
    }

    virtual std::shared_ptr<ByteArray> unwrap(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory>)
    {
        return data;
    }

    virtual std::shared_ptr<ByteArray> sign(std::shared_ptr<ByteArray> data, std::shared_ptr<io::MslEncoderFactory>,
            const io::MslEncoderFormat&)
    {
        (void) data;
        return std::make_shared<ByteArray>();
    }

    virtual bool verify(std::shared_ptr<ByteArray> data, std::shared_ptr<ByteArray> signature,
            std::shared_ptr<io::MslEncoderFactory>)
    {
        (void) data;
        (void) signature;
        return true;
    }

};

} /* namespace crypto */
} /* namespace msl */
} /* namespace netflix */

#endif /* SRC_CRYPTO_NULLCRYPTOCONTEXT_H_ */
