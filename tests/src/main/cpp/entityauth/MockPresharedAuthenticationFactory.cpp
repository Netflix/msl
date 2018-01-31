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

#include "MockPresharedAuthenticationFactory.h"
#include <MslInternalException.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/SymmetricCryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/PresharedAuthenticationData.h>
#include <io/MslEncoderFormat.h>
#include <MslEntityAuthException.h>

#include "../util/MslTestUtils.h"

using netflix::msl::MslInternalException;

using namespace std;
using namespace netflix::msl::util;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;

namespace netflix {
namespace msl {
typedef vector<uint8_t> ByteArray;
namespace entityauth {

namespace {

/** PSK Kpe. */
const char * PSK_KPE_B64 = "kzWYEtKSsPI8dOW5YyoILQ==";
/** PSK Kph. */
const char * PSK_KPH_B64 = "VhxNUK7bYIcCV4wLE2YK90do1X3XqhPeMwwllmNh8Jw=";

/** PSK Kpe 2. */
const char * PSK_KPE2_B64 = "lzWYEtKSsPI8dOW5YyoILQ==";
/** PSK Kph 2. */
const char * PSK_KPH2_B64 = "WhxNUK7bYIcCV4wLE2YK90do1X3XqhPeMwwllmNh8Jw=";

} // namespace anonymous

const shared_ptr<ByteArray> MockPresharedAuthenticationFactory::PSK_KPE = Base64::decode(PSK_KPE_B64);
const shared_ptr<ByteArray> MockPresharedAuthenticationFactory::PSK_KPH = Base64::decode(PSK_KPH_B64);
const string MockPresharedAuthenticationFactory::PSK_ESN = "PSK-ESN";
const SecretKey MockPresharedAuthenticationFactory::KPE(PSK_KPE, JcaAlgorithm::AES);
const SecretKey MockPresharedAuthenticationFactory::KPH(PSK_KPH, JcaAlgorithm::HMAC_SHA256);
const SecretKey MockPresharedAuthenticationFactory::KPW
(
    MslTestUtils::deriveWrappingKey(
        MockPresharedAuthenticationFactory::PSK_KPE,
        MockPresharedAuthenticationFactory::PSK_KPH
    ),
    JcaAlgorithm::AESKW
);

const shared_ptr<ByteArray> MockPresharedAuthenticationFactory::PSK_KPE2 = Base64::decode(PSK_KPE2_B64);
const shared_ptr<ByteArray> MockPresharedAuthenticationFactory::PSK_KPH2 = Base64::decode(PSK_KPH2_B64);
const string MockPresharedAuthenticationFactory::PSK_ESN2 = "PSK-ESN2";
const SecretKey MockPresharedAuthenticationFactory::KPE2(PSK_KPE2, JcaAlgorithm::AES);
const SecretKey MockPresharedAuthenticationFactory::KPH2(PSK_KPH2, JcaAlgorithm::HMAC_SHA256);
const SecretKey MockPresharedAuthenticationFactory::KPW2
(
    MslTestUtils::deriveWrappingKey(
        MockPresharedAuthenticationFactory::PSK_KPE2,
        MockPresharedAuthenticationFactory::PSK_KPH2
    ),
    JcaAlgorithm::AESKW
);

shared_ptr<EntityAuthenticationData> MockPresharedAuthenticationFactory::createData(shared_ptr<MslContext>,
        shared_ptr<MslObject> entityAuthMo)
{
    return make_shared<PresharedAuthenticationData>(entityAuthMo);
}

shared_ptr<ICryptoContext> MockPresharedAuthenticationFactory::getCryptoContext(shared_ptr<MslContext> ctx,
        shared_ptr<EntityAuthenticationData> authdata)
{
    // Make sure we have the right kind of entity authentication data.
    if (!instanceof<PresharedAuthenticationData>(authdata.get())) {
        stringstream ss;
        ss << "Incorrect authentication data type " << typeid(authdata.get()).name() << ".";
        throw MslInternalException(ss.str());
    }

     // Try to return the test crypto context.
     const string identity = authdata->getIdentity();
     if (PSK_ESN == identity)
         return make_shared<SymmetricCryptoContext>(ctx, identity, KPE, KPH, KPW);
     if (PSK_ESN2 == identity)
         return make_shared<SymmetricCryptoContext>(ctx, identity, KPE2, KPH2, KPW2);

     // Entity not found.
     throw nm::MslEntityAuthException(nm::MslError::ENTITY_NOT_FOUND, "psk " + identity).setEntityAuthenticationData(authdata);
}

}}} //namespace netflix::msl::entityauth


