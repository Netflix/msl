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
#include <entityauth/MockEccAuthenticationFactory.h>
#include <crypto/JcaAlgorithm.h>
#include <MslError.h>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::io;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace entityauth {

namespace {

/** ECC public key. */
const string ECC_PUBKEY_B64 =
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExgY6uU5xZkvDLVlo5PpKjhRJnyqS"
	"j4+LNcQ+x+kdPbZf1GwiJy2sRiJwghsXl9X8ffRpUqiLeNW0oOE/+dG2iw==";

/** ECC private key. */
const string ECC_PRIVKEY_B64 =
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrNqzpcZOpGRqlVGZ"
	"nelA4i7N/E96nJ8Ntk1ZXhPzKcChRANCAATGBjq5TnFmS8MtWWjk+kqOFEmfKpKP"
	"j4s1xD7H6R09tl/UbCInLaxGInCCGxeX1fx99GlSqIt41bSg4T/50baL";

} // namespace anonymous

#if 0 // FIXME

const string MockEccAuthenticationFactory::ECC_ESN = "ECCPREFIX-ESN";
const string MockEccAuthenticationFactory::ECC_PUBKEY_ID = "mockECCKeyId";
const PublicKey MockEccAuthenticationFactory::ECC_PUBKEY(Base64::decode(ECC_PUBKEY_B64), JcaAlgorithm::ECDSA);
const PrivateKey MockEccAuthenticationFactory::ECC_PRIVKEY(Base64::decode(ECC_PRIVKEY_B64), JcaAlgorithm::ECDSA);

/** @inheritDoc */
shared_ptr<EntityAuthenticationData> MockEccAuthenticationFactory::createData(shared_ptr<MslContext> ctx, shared_ptr<MslObject> entityAuthMo)
{
	return make_shared<EccAuthenticationData>(entityAuthMo);
}

/** @inheritDoc */
shared_ptr<ICryptoContext> MockEccAuthenticationFactory::getCryptoContext(shared_ptr<MslContext> ctx, shared_ptr<EntityAuthenticationData> authdata)
{
	// Make sure we have the right kind of entity authentication data.
	if (!instanceof<EccAuthenticationData>(authdata.get())) {
		stringstream ss;
		ss << "Incorrect authentication data type " + typeid(authdata).name() + ".";
		throw MslInternalException(ss.str());
	}
	shared_ptr<EccAuthenticationData> ead = dynamic_pointer_cast<EccAuthenticationData>(authdata);

	// Try to return the test crypto context.
	const string& pubkeyid = ead->getPublicKeyId();
	if (ECC_PUBKEY_ID == pubkeyid) {
		const string& identity = ead->getIdentity();
		return make_shared<EccCryptoContext>(identity, ECC_PRIVKEY, ECC_PUBKEY, EccCryptoContext::Mode::SIGN_VERIFY);
	}

	// Entity not found.
	throw MslEntityAuthException(MslError::ECC_PUBLICKEY_NOT_FOUND, pubkeyid).setEntityAuthenticationData(ead);
}

#endif

}}} // namespace netflix::msl::entityauth
