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

#ifndef SRC_CRYPTO_IRANDOM_H_
#define SRC_CRYPTO_IRANDOM_H_

#include <cstdint>
#include <vector>

namespace netflix {
namespace msl {
namespace crypto {

class IRandom
{
public:
	virtual bool nextBoolean() = 0;
    virtual void nextBytes(std::vector<uint8_t>& buffer) = 0;
    virtual int64_t nextLong() = 0;
    /**
     * Get a pseudorandom, uniformly distributed int32_t value between 0
     * (inclusive) and the specified value (exclusive). n must be positive.
     */
    virtual int64_t nextLong(uint64_t n) = 0;
    virtual int32_t nextInt() = 0;
    /**
     * Get a pseudorandom, uniformly distributed int32_t value between 0
     * (inclusive) and the specified value (exclusive). n must be positive.
     */
    virtual int32_t nextInt(uint32_t n) = 0;
protected:
    virtual ~IRandom() {}
};

}}} // namespace netflix::msl::crypto

#endif /* SRC_CRYPTO_IRANDOM_H_ */
