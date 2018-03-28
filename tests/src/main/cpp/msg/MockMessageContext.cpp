/**
 * Copyright (c) 2016-2018 Netflix, Inc.  All rights reserved.
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

#include "../msg/MockMessageContext.h"
#include <msg/MessageContext.h>
#include <crypto/ICryptoContext.h>
#include <crypto/IRandom.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/Key.h>
#include <crypto/OpenSslLib.h>
#include <crypto/SymmetricCryptoContext.h>
#include <keyx/DiffieHellmanExchange.h>
#include <keyx/AsymmetricWrappedExchange.h>
#include <keyx/KeyRequestData.h>
#include <keyx/SymmetricWrappedExchange.h>
#include <msg/MessageDebugContext.h>
#include <msg/MessageServiceTokenBuilder.h>
#include <msg/MessageOutputStream.h>
#include <tokens/MslUser.h>
#include <userauth/UserAuthenticationData.h>
#include <userauth/UserAuthenticationScheme.h>
#include <userauth/EmailPasswordAuthenticationData.h>
#include <util/MslContext.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../keyx/MockDiffieHellmanParameters.h"
#include "../userauth/MockEmailPasswordAuthenticationFactory.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::keyx;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace msg {

namespace {
const string DH_PARAMETERS_ID = "1";
const string RSA_KEYPAIR_ID = "rsaKeypairId";

/**
 * @param ctx MSL context.
 * @param bitlength key length in bits.
 * @return a new key of the specified bit length.
 * @throws CryptoException if there is an error creating the key.
 */
SecretKey getSecretKey(shared_ptr<MslContext> ctx, const int bitlength, const string& algorithm) {
    shared_ptr<ByteArray> keydata = make_shared<ByteArray>(bitlength / 8);
    ctx->getRandom()->nextBytes(*keydata);
    return SecretKey(keydata, algorithm);
}
} // namespace anonymous

MockMessageContext::MockMessageContext(shared_ptr<MslContext> ctx, const string& userId, const UserAuthenticationScheme& scheme)
	: encrypted_(false)
	, integrityProtected_(false)
	, nonReplayable_(false)
	, requestingTokens_(false)
	, userId_(userId)
{
	if (UserAuthenticationScheme::EMAIL_PASSWORD == scheme) {
		userAuthData_ = make_shared<EmailPasswordAuthenticationData>(MockEmailPasswordAuthenticationFactory::EMAIL, MockEmailPasswordAuthenticationFactory::PASSWORD);
	} else if (UserAuthenticationScheme::INVALID != scheme) {
		throw IllegalArgumentException("Unsupported authentication type: " + scheme.name());
	}

    {
        shared_ptr<DiffieHellmanParameters> params = MockDiffieHellmanParameters::getDefaultParameters();
        const DHParameterSpec paramSpec = params->getParameterSpec(MockDiffieHellmanParameters::DEFAULT_ID());
        ByteArray tmp1, tmp2;
        dhGenKeyPair(*paramSpec.getP(), *paramSpec.getG(), tmp1, tmp2);
        shared_ptr<ByteArray> publicKey = make_shared<ByteArray>(tmp1);
        shared_ptr<PrivateKey> privateKey = make_shared<PrivateKey>(make_shared<ByteArray>(tmp2), "DH");
        keyRequestData_.insert(make_shared<DiffieHellmanExchange::RequestData>(DH_PARAMETERS_ID, publicKey, privateKey));
    }

	{
		pair<PublicKey,PrivateKey> rsaKeyPair = MslTestUtils::generateRsaKeys("RSA", 512);
		shared_ptr<PublicKey> publicKey = make_shared<PublicKey>(rsaKeyPair.first);
		shared_ptr<PrivateKey> privateKey = make_shared<PrivateKey>(rsaKeyPair.second);
		keyRequestData_.insert(make_shared<AsymmetricWrappedExchange::RequestData>(RSA_KEYPAIR_ID,AsymmetricWrappedExchange::RequestData::Mechanism::RSA,
		        publicKey, privateKey));
	}
	{
		keyRequestData_.insert(make_shared<SymmetricWrappedExchange::RequestData>(SymmetricWrappedExchange::KeyId::PSK));
	}

	cryptoContexts_.insert(make_pair(SERVICE_TOKEN_NAME, make_shared<SymmetricCryptoContext>(ctx, SERVICE_TOKEN_NAME, getSecretKey(ctx, 128, JcaAlgorithm::AES), getSecretKey(ctx, 256, JcaAlgorithm::HMAC_SHA256), SecretKey())));
	cryptoContexts_.insert(make_pair(DEFAULT_SERVICE_TOKEN_NAME, make_shared<SymmetricCryptoContext>(ctx, DEFAULT_SERVICE_TOKEN_NAME, getSecretKey(ctx, 128, JcaAlgorithm::AES), getSecretKey(ctx, 256, JcaAlgorithm::HMAC_SHA256), SecretKey())));
}

void MockMessageContext::removeCryptoContext(const string& name)
{
	map<string,shared_ptr<ICryptoContext>>::iterator it = cryptoContexts_.find(name);
	if (it != cryptoContexts_.end())
		cryptoContexts_.erase(it);
}
shared_ptr<UserAuthenticationData> MockMessageContext::getUserAuthData(const ReauthCode& /*reauth*/, bool /*renewable*/, bool /*required*/)
{
    // Default implementation just returns the existing user authentication
    // data. Override to implement specific behavior.
	return userAuthData_;
}

void MockMessageContext::MockMessageContext::setKeyRequestData(set<shared_ptr<KeyRequestData>> keyRequestData)
{
	keyRequestData_.clear();
	keyRequestData_.insert(keyRequestData.begin(), keyRequestData.end());
}

void MockMessageContext::updateServiceTokens(shared_ptr<MessageServiceTokenBuilder> /*builder*/, bool /*handshake*/)
{}

void MockMessageContext::write(shared_ptr<MessageOutputStream> /*output*/)
{}

}}} // namespace netflix::msl::msg
