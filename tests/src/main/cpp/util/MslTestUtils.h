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

#ifndef TEST_UTIL_MSLTESTUTILS_H_
#define TEST_UTIL_MSLTESTUTILS_H_
#include <io/MslObject.h>
#include <memory>
#include <vector>
#include <stdint.h>
#include <set>

namespace netflix {
namespace msl {
typedef std::vector<uint8_t> ByteArray;
namespace crypto { class PublicKey; class PrivateKey; }
namespace io { class MslEncoderFactory; class MslEncodable; }
namespace tokens { class MasterToken; class UserIdToken; class ServiceToken; class MslUser; }
namespace util {

class MslContext;

/**
 * Helper functions common to many unit tests and mocks.
 */
namespace MslTestUtils {

/**
 * Parse a new {@link MslObject} from the {@link MslEncodable}.
 *
 * @param encoder the {@link MslEncoderFactory}.
 * @param encode a {@link MslEncodable}.
 * @return the {@link MslObject}
 * @throws MslEncoderException if there is an error encoding and converting
 *         the  object cannot be encoded and converted
 */
std::shared_ptr<io::MslObject> toMslObject(std::shared_ptr<io::MslEncoderFactory> encoder, std::shared_ptr<io::MslEncodable> encode);

/**
 * Returns an RSA key pair with the specified Web Crypto algorithm
 * and key length.
 *
 * @param algo Web Crypto algorithm.
 * @param {number} length key length in bits.
 * @return the RSA key pair.
 * @throws MslInternalException if unable to generate a key pair.
 */
std::pair<crypto::PublicKey,crypto::PrivateKey> generateRsaKeys(const std::string& algo, int length);

/**
 * Derives the pre-shared or model group keys AES-128 Key Wrap key from the
 * provided AES-128 encryption key and HMAC-SHA256 key.
 *
 * @param encryptionKey the encryption key.
 * @param hmacKey the HMAC key.
 * @return the wrapping key.
 */
std::shared_ptr<ByteArray> deriveWrappingKey(std::shared_ptr<ByteArray> encryptionKey, std::shared_ptr<ByteArray> hmacKey);

/**
 * Returns a master token with the identity of the MSL context entity
 * authentication data that is not renewable or expired.
 *
 * @param ctx MSL context.
 * @param sequenceNumber master token sequence number to use.
 * @param serialNumber master token serial number to use.
 * @return a new master token.
 * @throws MslEncodingException if there is an error encoding the JSON
 *         data.
 * @throws MslCryptoException if there is an error encrypting or signing
 *         the token data.
 */
std::shared_ptr<tokens::MasterToken> getMasterToken(std::shared_ptr<util::MslContext> ctx,
        int64_t sequenceNumber, int64_t serialNumber);

/**
 * Returns an untrusted master token with the identity of the MSL context
 * entity authentication data that is not renewable or expired.
 *
 * @param ctx MSL context.
 * @return a new untrusted master token.
 * @throws MslEncodingException if there is an error encoding the data.
 * @throws MslCryptoException if there is an error encrypting or signing
 *         the token data.
 * @throws MslException if the master token is constructed incorrectly.
 * @throws MslEncoderException if there is an error editing the data.
 */
std::shared_ptr<tokens::MasterToken> getUntrustedMasterToken(std::shared_ptr<util::MslContext> ctx);

/**
 * Returns a user ID token with the identity of the provided user that is
 * not renewable or expired.
 *
 * @param ctx MSL context.
 * @param masterToken master token to bind against.
 * @param serialNumber user ID token serial number to use.
 * @param user MSL user to use.
 * @return a new user ID token.
 * @throws MslEncodingException if there is an error encoding the JSON
 *         data.
 * @throws MslCryptoException if there is an error encrypting or signing
 *         the token data.
 */
std::shared_ptr<tokens::UserIdToken> getUserIdToken(std::shared_ptr<MslContext> ctx,
        std::shared_ptr<tokens::MasterToken> masterToken, int64_t serialNumber,
        std::shared_ptr<tokens::MslUser> user);

/**
 * Returns an untrusted user ID token with the identity of the provided
 * user that is not renewable or expired.
 *
 * @param ctx MSL context.
 * @param masterToken master token to bind against.
 * @param serialNumber user ID token serial number to use.
 * @param user MSL user to use.
 * @return a new untrusted user ID token.
 * @throws MslEncodingException if there is an error encoding the data.
 * @throws MslCryptoException if there is an error encrypting or signing
 *         the token data.
 * @throws MslEncoderException if there is an error editing the data.
 * @throws MslException if the user ID token serial number is out of range.
 */
std::shared_ptr<tokens::UserIdToken> getUntrustedUserIdToken(std::shared_ptr<util::MslContext> ctx,
        std::shared_ptr<tokens::MasterToken> masterToken, int64_t serialNumber,
        std::shared_ptr<tokens::MslUser> user);

/**
 * @param ctx MSL context.
 * @param masterToken master token to bind against. May be null.
 * @param userIdToken user ID token to bind against. May be null.
 * @return a set of new service tokens with random token bindings.
 * @throws MslEncodingException if there is an error encoding the JSON
 *         data.
 * @throws MslCryptoException if there is an error encrypting or signing
 *         the token data.
 * @throws MslException if there is an error compressing the data.
 */
std::set<std::shared_ptr<tokens::ServiceToken>> getServiceTokens(std::shared_ptr<util::MslContext> ctx,
        std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken);

/**
 * @param ctx MSL context.
 * @param masterToken the master token to bind against.
 * @return a random set of master token bound service tokens.
 * @throws MslEncodingException if there is an error constructing the
 *         service token.
 * @throws MslCryptoException if there is an error constructing the service
 *         token.
 * @throws MslException if there is an error compressing the data.
 */
std::set<std::shared_ptr<tokens::ServiceToken>> getMasterBoundServiceTokens(std::shared_ptr<MslContext> ctx,
		std::shared_ptr<tokens::MasterToken> masterToken);

/**
 * @param ctx MSL context.
 * @param masterToken the master token to bind against.
 * @param userIdToken the user ID token to bind against.
 * @return a random set of user ID token bound service tokens.
 * @throws MslEncodingException if there is an error constructing the
 *         service token.
 * @throws MslCryptoException if there is an error constructing the service
 *         token.
 * @throws MslException if there is an error compressing the data.
 */
std::set<std::shared_ptr<tokens::ServiceToken>> getUserBoundServiceTokens(std::shared_ptr<MslContext> ctx,
		std::shared_ptr<tokens::MasterToken> masterToken, std::shared_ptr<tokens::UserIdToken> userIdToken);

/**
 * Compare two shared_ptr sets for equality.
 *
 * @param a first set.
 * @param b second set.
 * @return true if the contents of the two sets are equal.
 */
template<typename T>
bool equal(std::set<std::shared_ptr<T>> a, std::set<std::shared_ptr<T>> b)
{
	// FIXME: Replace with MessageHeader::sharedPtrSetEq()
	if (a.size() != b.size()) return false;

	// For each element in a...
	for (typename std::set<std::shared_ptr<T>>::const_iterator aElements = a.begin();
		 aElements != a.end();
		 ++aElements)
	{
		std::shared_ptr<T> aElement = *aElements;

		// Make sure it exists in b.
		bool found = false;
		for (typename std::set<std::shared_ptr<T>>::const_iterator bElements = b.begin();
			 bElements != b.end();
			 ++bElements)
		{
			std::shared_ptr<T> bElement = *bElements;
			if (*aElement == *bElement) {
				found = true;
				break;
			}
		}

		// If not found, not equal.
		if (!found) return false;
	}

	// Equal.
	return true;
}

/**
 * Merge two shared_ptr sets into a third set.
 *
 * @param a first set.
 * @param b second set.
 * @return a new set containing the contents of both sets.
 */
template<typename T>
std::set<std::shared_ptr<T>> merge(std::set<std::shared_ptr<T>> a, std::set<std::shared_ptr<T>> b)
{
	// Make a shallow copy of a.
	std::set<std::shared_ptr<T>> c(a);

	// For each element in b...
	for (typename std::set<std::shared_ptr<T>>::const_iterator bElements = b.begin();
		 bElements != b.end();
		 ++bElements)
	{
		std::shared_ptr<T> bElement = *bElements;

		// Check if the element exists in a...
		bool exists = false;
		for (typename std::set<std::shared_ptr<T>>::const_iterator aElements = a.begin();
			 aElements != a.end();
			 ++aElements)
		{
			std::shared_ptr<T> aElement = *aElements;
			if (*aElement == *bElement) {
				exists = true;
				break;
			}
		}

		// Copy into c if the element did not exist in a.
		if (!exists)
			c.insert(bElement);
	}

	return c;
}

/**
 * Remove the contents of one shared_ptr set from another.
 *
 * @param a first set.
 * @param b second set.
 * @return a new set containing the contents of the first set minus the
 *         contents of the second.
 */
template<typename T>
std::set<std::shared_ptr<T>> remove(std::set<std::shared_ptr<T>> a, std::set<std::shared_ptr<T>> b)
{
	// Make a shallow copy of a
	std::set<std::shared_ptr<T>> c(a);

	// For each element in b...
	for (typename std::set<std::shared_ptr<T>>::const_iterator bElements = b.begin();
		 bElements != b.end();
		 ++bElements)
	{
		std::shared_ptr<T> bElement = *bElements;

		// Remove the element if it exists in c.
		for (typename std::set<std::shared_ptr<T>>::iterator cElements = c.begin();
			 cElements != c.end();
			 ++cElements)
		{
			std::shared_ptr<T> cElement = *cElements;

			if (*cElement == *bElement) {
				c.erase(cElements);
				break;
			}
		}
	}

	return c;
}

}}}} // namespace netflix::msl::util::MslTestUtils

#endif /* TEST_UTIL_MSLTESTUTILS_H_ */
