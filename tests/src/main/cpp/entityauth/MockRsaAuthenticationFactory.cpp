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

#include "MockRsaAuthenticationFactory.h"

#include <MslInternalException.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/RsaCryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/RsaAuthenticationData.h>
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

/** 1024-bit RSA public key. */
const char * RSA_PUBKEY_B64 =
    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALeJpiH5nikd3XeAo2rHjLJVVChM/p6l"
    "VnQHyFh77w0Efbppi1P1pNy8BxJ++iFKt2dV/4ZKkUKqtlIu3KX19kcCAwEAAQ==";
/** 1024-bit RSA private key. */
const char * RSA_PRIVKEY_B64 =
    "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAt4mmIfmeKR3dd4Cj"
    "aseMslVUKEz+nqVWdAfIWHvvDQR9ummLU/Wk3LwHEn76IUq3Z1X/hkqRQqq2Ui7c"
    "pfX2RwIDAQABAkEAlB6YXq7uv0wE4V6Fg7VLjNhkNKn+itXwMW/eddp/D8cC4QbH"
    "+0Ejt0e3F+YcY0RBsTUk7hz89VW7BtpjXRrU0QIhAOyjvUsihGzImq+WDiEWvnXX"
    "lVaUaJXaaNElE37V/BE1AiEAxo25k2z2SDbFC904Zk020kISi95KNNv5ceEFcGu0"
    "dQsCIQDUgj7uCHNv1b7ETDcoE+q6nP2poOFDIb7bgzY8wyH4uQIgf+02YO82auam"
    "5HL+8KLVLHkXm/h31UDZoe66Y2lxlmsCIQC+cKulQATpKNnMV1RVtpH07A0+X72s"
    "wpu2pmaRSYgw/w==";

} // namespace anonymous

const string MockRsaAuthenticationFactory::RSA_ESN = "RSAPREFIX-ESN";
const string MockRsaAuthenticationFactory::RSA_PUBKEY_ID = "mockRSAKeyId";
const PublicKey MockRsaAuthenticationFactory::RSA_PUBKEY(Base64::decode(RSA_PUBKEY_B64), JcaAlgorithm::SHA256withRSA);
const PrivateKey MockRsaAuthenticationFactory::RSA_PRIVKEY(Base64::decode(RSA_PRIVKEY_B64), JcaAlgorithm::SHA256withRSA);

shared_ptr<EntityAuthenticationData> MockRsaAuthenticationFactory::createData(shared_ptr<MslContext>,
        shared_ptr<MslObject> entityAuthMo)
{
    return make_shared<RsaAuthenticationData>(entityAuthMo);
}

shared_ptr<ICryptoContext> MockRsaAuthenticationFactory::getCryptoContext(shared_ptr<MslContext> ctx,
        shared_ptr<EntityAuthenticationData> authdata)
{
    // Make sure we have the right kind of entity authentication data.
    if (!instanceof<RsaAuthenticationData>(authdata.get())) {
        stringstream ss;
        ss << "Incorrect authentication data type " << typeid(authdata).name() << ".";
        throw MslInternalException(ss.str());
    }
    shared_ptr<RsaAuthenticationData> rad = dynamic_pointer_cast<RsaAuthenticationData>(authdata);

     // Try to return the test crypto context.
     const string& pubkeyid = rad->getPublicKeyId();
     if (RSA_PUBKEY_ID == pubkeyid) {
    	 const string& identity = rad->getIdentity();
    	 return make_shared<RsaCryptoContext>(ctx, identity, RSA_PRIVKEY, RSA_PUBKEY, RsaCryptoContext::Mode::SIGN_VERIFY);
     }

     // Entity not found.
     throw nm::MslEntityAuthException(nm::MslError::ENTITY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(rad);
}

}}} //namespace netflix::msl::entityauth
