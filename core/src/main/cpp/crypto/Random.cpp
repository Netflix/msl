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

#include "Random.h"
#include <MslInternalException.h>
#include "OpenSslLib.h"
#include <assert.h>
#include <cstdlib>
#include <limits>
#include <openssl/rand.h>

namespace netflix {
namespace msl {
namespace crypto {

namespace {

// Returns random integer within full signed range of T
template <typename T>
T nextInteger(IRandom* random)
{
    std::vector<uint8_t> buffer(sizeof(T));
    random->nextBytes(buffer);
    T result = 0;
    // Note: Since buffer[i] is an unsigned type, casting to a larger type
    // (either signed or unsigned) does not sign extend. See
    // https://www.securecoding.cert.org/confluence/display/c/STR34-C.+Cast+characters+to+unsigned+char+before+converting+to+larger+integer+sizes
    for (size_t i = 0; i < sizeof(T); ++i)
        result |= static_cast<T>(buffer[i]) << i*8;
    return result;
}

// Returns random integer in range [0, n)
// This algorithm assures that the distribution of the underlying RNG is
// retained. The idea is to divide the range of the RNG into an integral number
// q of n-sized buckets, pull from the RNG until we find a number in the range
// [0, nq), then return this result mod n.
// See Cryptography Engineering: Ferguson, Schneier, Kohno, 2010, Section 9.7 p160.
template <typename T>
T nextIntegerBounded(T n, IRandom* random)
{
    if (n < 2)
        throw MslInternalException("Random range max must be >= 2");
    const T q = std::numeric_limits<T>::max()/n;
    T r;
    do {
        r = nextInteger<T>(random);
        if (r < 0) r = -r;
    } while (r >= n*q);
    return r % n;
}

} // namespace anonymous

Random::Random()
{
    ensureOpenSslInit();
}

void Random::nextBytes(std::vector<uint8_t>& buffer)
{
    const size_t nBytes = buffer.size();
    assert(nBytes);
    if (!nBytes)
        return;
    if (RAND_bytes(&buffer[0], (int)nBytes) != 1)
        throw MslInternalException("RAND_bytes error!");
}

bool Random::nextBoolean()
{
	std::vector<uint8_t> buffer(1);
	nextBytes(buffer);
	return buffer[0] & 0x1;
}

int32_t Random::nextInt()
{
    return nextInteger<int32_t>(this);
}

int64_t Random::nextLong()
{
    return nextInteger<int64_t>(this);
}

int32_t Random::nextInt(uint32_t n)
{
    return nextIntegerBounded<int32_t>(static_cast<int32_t>(n), this);
}

int64_t Random::nextLong(uint64_t n)
{
    return nextIntegerBounded<int64_t>(static_cast<int64_t>(n), this);
}

}}} // namespace netflix::msl::crypto
