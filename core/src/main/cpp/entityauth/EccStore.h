/**
 * Copyright (c) 2018 Netflix, Inc.  All rights reserved.
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
#ifndef SRC_ENTITYAUTH_ECCSTORE_H_
#define SRC_ENTITYAUTH_ECCSTORE_H_

#include <memory>
#include <set>
#include <string>

namespace netflix {
namespace msl {
namespace crypto { class PublicKey; class PrivateKey; }
namespace entityauth {

/**
 * An ECC public key store contains trusted ECC public and private keys.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class EccStore
{
public:
    virtual ~EccStore() {}

    /**
     * @return the known key pair identities.
     */
    std::set<std::string> getIdentities() = 0;

    /**
     * Return the public key of the identified ECC key pair.
     *
     * @param identity ECC key pair identity.
     * @return the public key of the identified key pair or null if not found.
     */
    std::shared_ptr<crypto::PublicKey> getPublicKey(const std::string& identity) = 0;

    /**
     * Return the private key of the identified ECC key pair.
     *
     * @param identity ECC key pair identity.
     * @return the private key of the identified key pair or null if not found.
     */
    std::shared_ptr<crypto::PrivateKey> getPrivateKey(const std::string& identity) = 0;
};

}}} // namespace netflix::msl::entityauth

#endif /* SRC_ENTITYAUTH_ECCSTORE_H_ */
