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

#include "MockPresharedProfileAuthenticationFactory.h"
#include <crypto/JcaAlgorithm.h>
#include <crypto/SymmetricCryptoContext.h>
#include <entityauth/PresharedProfileAuthenticationData.h>
#include <io/MslEncoderFormat.h>
#include <Macros.h>
#include <MslEntityAuthException.h>
#include <MslError.h>
#include <MslInternalException.h>
#include <util/Base64.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "../util/MslTestUtils.h"

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
typedef vector<uint8_t> ByteArray;
namespace entityauth {

namespace {
const string PSK_KPE_B64 = "kzWYEtKSsPI8dOW5YyoILQ==";
const string PSK_KPH_B64 = "VhxNUK7bYIcCV4wLE2YK90do1X3XqhPeMwwllmNh8Jw=";
const string PSK_KPE2_B64 = "lzWYEtKSsPI8dOW5YyoILQ==";
const string PSK_KPH2_B64 = "WhxNUK7bYIcCV4wLE2YK90do1X3XqhPeMwwllmNh8Jw=";

} // namespace anonymous

const std::string MockPresharedProfileAuthenticationFactory::PSK_ESN = "PSK-ESN";
const std::string MockPresharedProfileAuthenticationFactory::PSK_ESN2 = "PSK-ESN2";
const std::string MockPresharedProfileAuthenticationFactory::PROFILE = "PROFILE";


MockPresharedProfileAuthenticationFactory::MockPresharedProfileAuthenticationFactory()
: EntityAuthenticationFactory(EntityAuthenticationScheme::PSK_PROFILE)
, PSK_KPE(Base64::decode(PSK_KPE_B64))
, PSK_KPH(Base64::decode(PSK_KPH_B64))
, PSK_KPE2(Base64::decode(PSK_KPE2_B64))
, PSK_KPH2(Base64::decode(PSK_KPH2_B64))
, KPE(PSK_KPE, JcaAlgorithm::AES)
, KPH(PSK_KPH, JcaAlgorithm::HMAC_SHA256)
, KPW(MslTestUtils::deriveWrappingKey(PSK_KPE, PSK_KPH), JcaAlgorithm::AESKW)
, KPE2(PSK_KPE2, JcaAlgorithm::AES)
, KPH2(PSK_KPH2, JcaAlgorithm::HMAC_SHA256)
, KPW2(MslTestUtils::deriveWrappingKey(PSK_KPE2, PSK_KPH2), JcaAlgorithm::AESKW)
{}

shared_ptr<EntityAuthenticationData> MockPresharedProfileAuthenticationFactory::createData(
        shared_ptr<MslContext>,
        shared_ptr<MslObject> entityAuthMo)
{
    return make_shared<PresharedProfileAuthenticationData>(entityAuthMo);
}

shared_ptr<ICryptoContext> MockPresharedProfileAuthenticationFactory::getCryptoContext(
        shared_ptr<MslContext> ctx,
        shared_ptr<EntityAuthenticationData> authdata)
{
    // Make sure we have the right kind of entity authentication data.
    if (!(instanceof<PresharedProfileAuthenticationData>(authdata.get())))
        throw MslInternalException("Incorrect authentication data type.");
    shared_ptr<PresharedProfileAuthenticationData> ppad = dynamic_pointer_cast<PresharedProfileAuthenticationData>(authdata);

    // Try to return the test crypto context.
    const string pskId = ppad->getPresharedKeysId();
    const string identity = ppad->getIdentity();
    if (pskId == PSK_ESN)
        return make_shared<SymmetricCryptoContext>(ctx, identity, KPE, KPH, KPW);
    if (pskId == PSK_ESN2)
        return make_shared<SymmetricCryptoContext>(ctx, identity, KPE2, KPH2, KPW2);

    // Entity not found.
    throw MslEntityAuthException(MslError::ENTITY_NOT_FOUND, "psk profile " + pskId).setEntityAuthenticationData(ppad);
}

}}} // namespace netflix::msl::entityauth
