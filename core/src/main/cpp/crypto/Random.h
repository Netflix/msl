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

#ifndef SRC_MSLRANDOM_H_
#define SRC_MSLRANDOM_H_

#include <crypto/IRandom.h>
#include <Macros.h>
#include <stdint.h>

namespace netflix {
namespace msl {
namespace crypto {

class Random : public IRandom
{
public:
    Random();
    virtual ~Random() {}
    virtual bool nextBoolean();
    virtual void nextBytes(std::vector<uint8_t>& buffer);
    virtual int64_t nextLong();
    virtual int64_t nextLong(uint64_t n); // returns value in range [0, n)
    virtual int32_t nextInt();
    virtual int32_t nextInt(uint32_t n); // returns value in range [0, n)
private:
    void foo();
    DISALLOW_COPY_AND_ASSIGN(Random);
};

}}} // namespace netflix::msl::crypto

#endif /* SRC_MSLRANDOM_H_ */
