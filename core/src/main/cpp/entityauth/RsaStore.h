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

#ifndef SRC_ENTITYAUTH_PRESHAREDKEYSTORE_H_
#define SRC_ENTITYAUTH_PRESHAREDKEYSTORE_H_

#include <crypto/Key.h>
#include <set>
#include <string>

namespace netflix {
namespace msl {
namespace entityauth {

class RsaStore
{
public:
    virtual ~RsaStore() {}

    /**
     * @return the known key pair identities.
     */
    virtual std::set<std::string> getIdentities() = 0;

    /**
     * Return the public key of the identified RSA key pair.
     *
     * @param identity RSA key pair identity.
     * @return the public key of the identified key pair or null if not found.
     */
    virtual crypto::PublicKey getPublicKey(const std::string& identity) = 0;

    /**
     * Return the private key of the identified RSA key pair.
     *
     * @param identity RSA key pair identity.
     * @return the private key of the identified key pair or null if not found.
     */
    virtual crypto::PrivateKey getPrivateKey(const std::string& identity) = 0;
};

}}} // namespace netflix::msl::entityauth

#endif /* SRC_ENTITYAUTH_PRESHAREDKEYSTORE_H_ */
