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

#include <util/MslUtils.h>
#include <crypto/IRandom.h>
#include <util/Base64.h>
#include <util/MslContext.h>
#include <assert.h>
#include <MslError.h>
#include <MslException.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslKeyExchangeException.h>
#include <MslMasterTokenException.h>
#include <MslMessageException.h>
#include <MslUserAuthException.h>
#include <MslUserIdTokenException.h>
#include <string.h>
#include <zlib.h>
#include <algorithm>
#include <sstream>
#include <streambuf>
#include <memory>

using namespace std;
using namespace netflix::msl::crypto;

namespace {

bool insStringCompare_pred(unsigned char a, unsigned char b) {
    return tolower(a) == tolower(b);
}

/**
 * Return true if the number is a non-negative power of two. Zero is
 * considered a power of two and will return true.
 *
 * @param n the number to test.
 * @return true if the number is a non-negative power of two.
 */
bool is_power_of_2(int64_t n) {
    // If the number is a power of two, a binary AND operation between
    // the number and itself minus one will equal zero.
	if (n < 0) return false;
    if (n == 0) return true;
    return (n & (n - 1)) == 0;
}

} // namespace anonymous

namespace netflix {
namespace msl {
namespace util {

namespace MslUtils {

void rethrow(const MslException& e)
{
	if (instanceof<MslCryptoException>(&e))
		throw *dynamic_cast<const MslCryptoException*>(&e);

	if (instanceof<MslEncodingException>(&e))
		throw *dynamic_cast<const MslEncodingException*>(&e);

	if (instanceof<MslEntityAuthException>(&e))
		throw *dynamic_cast<const MslEntityAuthException*>(&e);

	if (instanceof<MslKeyExchangeException>(&e))
		throw *dynamic_cast<const MslKeyExchangeException*>(&e);

	if (instanceof<MslMasterTokenException>(&e))
		throw *dynamic_cast<const MslMasterTokenException*>(&e);

	if (instanceof<MslMessageException>(&e))
		throw *dynamic_cast<const MslMessageException*>(&e);

	if (instanceof<MslUserAuthException>(&e))
		throw *dynamic_cast<const MslUserAuthException*>(&e);

	if (instanceof<MslUserIdTokenException>(&e))
		throw *dynamic_cast<const MslUserIdTokenException*>(&e);

	throw e;
}

void rethrow(shared_ptr<IException> e)
{
	if (dynamic_pointer_cast<MslCryptoException>(e))
		throw *dynamic_pointer_cast<MslCryptoException>(e);

	if (dynamic_pointer_cast<MslEncodingException>(e))
		throw *dynamic_pointer_cast<MslEncodingException>(e);

	if (dynamic_pointer_cast<MslEntityAuthException>(e))
		throw *dynamic_pointer_cast<MslEntityAuthException>(e);

	if (dynamic_pointer_cast<MslKeyExchangeException>(e))
		throw *dynamic_pointer_cast<MslKeyExchangeException>(e);

	if (dynamic_pointer_cast<MslMasterTokenException>(e))
		throw *dynamic_pointer_cast<MslMasterTokenException>(e);

	if (dynamic_pointer_cast<MslMessageException>(e))
		throw *dynamic_pointer_cast<MslMessageException>(e);

	if (dynamic_pointer_cast<MslUserAuthException>(e))
		throw *dynamic_pointer_cast<MslUserAuthException>(e);

	if (dynamic_pointer_cast<MslUserIdTokenException>(e))
		throw *dynamic_pointer_cast<MslUserIdTokenException>(e);

	if (dynamic_pointer_cast<MslException>(e))
		throw *dynamic_pointer_cast<MslException>(e);
}

// Case-insensitive string compare.
bool insStringCompare(std::string const& a, std::string const& b)
{
    if (a.size() != b.size()) return false;
    return equal(b.begin(), b.end(), a.begin(), insStringCompare_pred);
}

int64_t getRandomLong(shared_ptr<MslContext> ctx) {
    // If the maximum long value is a power of 2, then we can perform a
    // bitmask on the randomly generated long value to restrict to our
    // target number space.
    bool isPowerOf2 = is_power_of_2(MslConstants::MAX_LONG_VALUE);

    // Generate the random value.
    shared_ptr<IRandom> r = ctx->getRandom();
    int64_t n = -1;
    do {
        n = r->nextLong();

        // Perform a bitmask if permitted, which will force this loop
        // to exit immediately.
        if (isPowerOf2)
            n &= (MslConstants::MAX_LONG_VALUE - 1);
    } while (n < 0 || n > MslConstants::MAX_LONG_VALUE);

    // Return the random value.
    return n;
}

} // namespace MslUtils

}}} // namespace netflix::msl::util
