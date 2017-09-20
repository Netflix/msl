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

#ifndef TEST_ENTITYAUTH_MOCKRSASTORE_H_
#define TEST_ENTITYAUTH_MOCKRSASTORE_H_

#include <crypto/Key.h>
#include <entityauth/RsaStore.h>
#include <map>
#include <set>
#include <string>

namespace netflix {
namespace msl {
namespace entityauth {

/**
 * Test RSA key store.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class MockRsaStore : public RsaStore
{
public:
	virtual ~MockRsaStore() {}

	/** @inheritDoc */
    virtual std::set<std::string> getIdentities();

    /** @inheritDoc */
    virtual crypto::PublicKey getPublicKey(const std::string& identity);

    /** @inheritDoc */
    virtual crypto::PrivateKey getPrivateKey(const std::string& identity);

    /**
     * Add an RSA public key to the store.
     *
     * @param identity RSA key pair identity.
     * @param pubkey RSA public key.
     * @throws IllegalArgumentException if the public key is not a
     *         {@link RSAPublicKey}.
     */
    void addPublicKey(const std::string& identity, const crypto::PublicKey& pubkey);

    /**
     * Add an RSA private key to the store.
     *
     * @param identity RSA key pair identity.
     * @param privkey RSA private key.
     * @throws IllegalArgumentException if the private key is not a
     *         {@link RSAPrivateKey}.
     */
    void addPrivateKey(const std::string& identity, const crypto::PrivateKey& privkey);

    /**
     * <p>Clear the store of all public and private keys.</p>
     */
    void clear();

private:
    /** Public keys. */
    std::map<std::string,crypto::PublicKey> keys_;
    /** Private keys. */
    std::map<std::string,crypto::PrivateKey> privateKeys_;
};

}}} // namespace netflix::msl::entityauth

#endif /* TEST_ENTITYAUTH_MOCKRSASTORE_H_ */
