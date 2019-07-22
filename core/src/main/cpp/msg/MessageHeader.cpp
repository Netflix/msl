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

#include <crypto/SessionCryptoContext.h>
#include <entityauth/EntityAuthenticationData.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <entityauth/EntityAuthenticationFactory.h>
#include <userauth/UserAuthenticationData.h>
#include <userauth/UserAuthenticationFactory.h>
#include <io/MslEncodable.h>
#include <io/MslEncoderFactory.h>
#include <io/MslEncoderUtils.h>
#include <io/MslVariant.h>
#include <msg/MessageHeader.h>
#include <msg/HeaderKeys.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyRequestData.h>
#include <Macros.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslEntityAuthException.h>
#include <MslInternalException.h>
#include <MslMasterTokenException.h>
#include <MslMessageException.h>
#include <MslUserAuthException.h>
#include <tokens/ServiceToken.h>
#include <tokens/MasterToken.h>
#include <tokens/UserIdToken.h>
#include <stdint.h>
#include <util/MslContext.h>
#include <util/MslStore.h>
#include <util/MslUtils.h>
#include <set>
#include <vector>

using namespace std;
using namespace netflix::msl;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::keyx;
using namespace netflix::msl::io;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace msg {

namespace {
/** Milliseconds per second. */
const int64_t MILLISECONDS_PER_SECOND = 1000;

// Message header data.
/** Key sender. */
const string KEY_SENDER = "sender";
/** Key timestamp. */
const string KEY_TIMESTAMP = "timestamp";
/** Key message ID. */
const string KEY_MESSAGE_ID = "messageid";
/** Key non-replayable ID. */
const string KEY_NON_REPLAYABLE_ID = "nonreplayableid";
/** Key non-replayable flag. */
const string KEY_NON_REPLAYABLE = "nonreplayable";
/** Key renewable flag. */
const string KEY_RENEWABLE = "renewable";
/** Key handshake flag */
const string KEY_HANDSHAKE = "handshake";
/** Key capabilities. */
const string KEY_CAPABILITIES = "capabilities";
/** Key key exchange request. */
const string KEY_KEY_REQUEST_DATA = "keyrequestdata";
/** Key key exchange response. */
const string KEY_KEY_RESPONSE_DATA = "keyresponsedata";
/** Key user authentication data. */
const string KEY_USER_AUTHENTICATION_DATA = "userauthdata";
/** Key user ID token. */
const string KEY_USER_ID_TOKEN = "useridtoken";
/** Key service tokens. */
const string KEY_SERVICE_TOKENS = "servicetokens";

// Message header peer data.
/** Key peer master token. */
const string KEY_PEER_MASTER_TOKEN = "peermastertoken";
/** Key peer user ID token. */
const string KEY_PEER_USER_ID_TOKEN = "peeruseridtoken";
/** Key peer service tokens. */
const string KEY_PEER_SERVICE_TOKENS = "peerservicetokens";

// T must be derived from MslEncodable
template <typename T>
vector<Variant> mslEncodableVector(const set<shared_ptr<T>>& s)
{
    vector<Variant> result;
    for (typename set<shared_ptr<T>>::const_iterator it = s.begin(); it != s.end(); ++it)
    {
        shared_ptr<MslEncodable> mslEncodable = dynamic_pointer_cast<MslEncodable>(*it);
        Variant variant = VariantFactory::create(mslEncodable);
        result.push_back(variant);
    }
    return result;
}

} // namespace anonymous

MessageHeader::HeaderData::HeaderData(int64_t messageId, int64_t nonReplayableId,
        bool renewable, bool handshake, shared_ptr<MessageCapabilities> capabilities,
        set<shared_ptr<KeyRequestData>> keyRequestData, shared_ptr<KeyResponseData> keyResponseData,
        shared_ptr<UserAuthenticationData> userAuthData, shared_ptr<UserIdToken> userIdToken,
        set<shared_ptr<ServiceToken>> serviceTokens)
    : messageId(messageId)
    , nonReplayableId(nonReplayableId)
    , renewable(renewable)
    , handshake(handshake)
    , capabilities(capabilities)
    , keyRequestData(keyRequestData)
    , keyResponseData(keyResponseData)
    , userAuthData(userAuthData)
    , userIdToken(userIdToken)
    , serviceTokens(serviceTokens)
{
}

MessageHeader::HeaderPeerData::HeaderPeerData(shared_ptr<MasterToken> peerMasterToken,
        shared_ptr<UserIdToken> peerUserIdToken, set<shared_ptr<ServiceToken>> peerServiceTokens)
    : peerMasterToken(peerMasterToken)
    , peerUserIdToken(peerUserIdToken)
    , peerServiceTokens(peerServiceTokens)
{
}

MessageHeader::MessageHeader(shared_ptr<MslContext> ctx, shared_ptr<EntityAuthenticationData> ead,
        shared_ptr<MasterToken> mt, shared_ptr<HeaderData> headerData, shared_ptr<HeaderPeerData> peerData)
: serviceTokens(headerData->serviceTokens)
{
    // Message ID must be within range.
    if (headerData->messageId < 0 || headerData->messageId > MslConstants::MAX_LONG_VALUE) {
        stringstream ss;
        ss << "Message ID " << headerData->messageId << " is out of range.";
        throw MslInternalException(ss.str());
    }

    // Message entity must be provided.
    if (!ead && !mt)
        throw MslInternalException("Message entity authentication data or master token must be provided.");

    // Do not allow user authentication data to be included if the message
    // will not be encrypted.
    bool encrypted;
    if (mt) {
        encrypted = true;
    } else {
        EntityAuthenticationScheme scheme = ead->getScheme();
        encrypted = scheme.encrypts();
    }
    if (!encrypted && headerData->userAuthData)
        throw MslInternalException("User authentication data cannot be included if the message is not encrypted.");

    // Older MSL stacks expect the sender if a master token is being used.
    //
    // If the local entity does not know its entity identity, then use the
    // empty string. This will work except for the case where the old MSL
    // stack is receiving a message for which it is also the issuer of the
    // master token. That scenario will continue to fail.
    shared_ptr<string> sender;
    if (mt) {
        const string localIdentity = ctx->getEntityAuthenticationData()->getIdentity();
        sender = make_shared<string>(localIdentity);
    }

    entityAuthData = (!mt) ? ead : shared_ptr<EntityAuthenticationData>();
    masterToken = mt;
    nonReplayableId = headerData->nonReplayableId;
    renewable = headerData->renewable;
    handshake = headerData->handshake;
    capabilities = headerData->capabilities;
    timestamp = ctx->getTime() / MILLISECONDS_PER_SECOND;
    messageId = headerData->messageId;
    keyRequestData = headerData->keyRequestData;
    keyResponseData = headerData->keyResponseData;
    userAuthData = headerData->userAuthData;
    userIdToken = headerData->userIdToken;
    if (ctx->isPeerToPeer()) {
        peerMasterToken = peerData->peerMasterToken;
        peerUserIdToken = peerData->peerUserIdToken;
        peerServiceTokens = peerData->peerServiceTokens;
    } else {
        peerMasterToken = shared_ptr<MasterToken>();
        peerUserIdToken = shared_ptr<UserIdToken>();
        // peerServiceTokens = ;  leave default constructed empty
    }

    // Grab token verification master tokens.
    shared_ptr<MasterToken>tokenVerificationMasterToken, peerTokenVerificationMasterToken;
    if (keyResponseData) {
        // The key response data is used for token verification in a
        // trusted services network and peer token verification in a peer-
        // to-peer network.
        if (!ctx->isPeerToPeer()) {
            tokenVerificationMasterToken = keyResponseData->getMasterToken();
            peerTokenVerificationMasterToken = peerMasterToken;
        } else {
            tokenVerificationMasterToken = masterToken;
            peerTokenVerificationMasterToken = keyResponseData->getMasterToken();
        }
    } else {
        tokenVerificationMasterToken = masterToken;
        peerTokenVerificationMasterToken = peerMasterToken;
    }

    // Check token combinations.
    if (userIdToken && (!tokenVerificationMasterToken || !userIdToken->isBoundTo(tokenVerificationMasterToken)))
        throw MslInternalException("User ID token must be bound to a master token.");
    if (peerUserIdToken && (!peerTokenVerificationMasterToken || !peerUserIdToken->isBoundTo(peerTokenVerificationMasterToken)))
        throw MslInternalException("Peer user ID token must be bound to a peer master token.");

    // Grab the user.
    if (userIdToken)
        user = userIdToken->getUser();
    else
        user = shared_ptr<MslUser>();

    // All service tokens must be unbound or if bound, bound to the
    // provided tokens.
    for (set<shared_ptr<ServiceToken>>::const_iterator it = serviceTokens.begin(); it != serviceTokens.end(); ++it) {
        const shared_ptr<ServiceToken> serviceToken = (*it);
        if (serviceToken->isMasterTokenBound() && (!tokenVerificationMasterToken || !serviceToken->isBoundTo(tokenVerificationMasterToken)))
            throw MslInternalException("Master token bound service tokens must be bound to the provided master token.");
        if (serviceToken->isUserIdTokenBound() && (!userIdToken || !serviceToken->isBoundTo(userIdToken)))
            throw MslInternalException("User ID token bound service tokens must be bound to the provided user ID token.");
    }
    for (set<shared_ptr<ServiceToken>>::const_iterator it = peerServiceTokens.begin(); it != peerServiceTokens.end(); ++it) {
        const shared_ptr<ServiceToken> serviceToken = (*it);
        if (serviceToken->isMasterTokenBound() && (!peerTokenVerificationMasterToken || !serviceToken->isBoundTo(peerTokenVerificationMasterToken)))
            throw MslInternalException("Master token bound peer service tokens must be bound to the provided peer master token.");
        if (serviceToken->isUserIdTokenBound() && (!peerUserIdToken || !serviceToken->isBoundTo(peerUserIdToken)))
            throw MslInternalException("User ID token bound peer service tokens must be bound to the provided peer user ID token.");
    }

    // Construct the header data.
    try {
        shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
        const set<MslEncoderFormat> formats = (capabilities) ? capabilities->getEncoderFormats() : set<MslEncoderFormat>();
        const MslEncoderFormat format = encoder->getPreferredFormat(formats);
        headerdata = encoder->createObject();
        if (sender) headerdata->put(KEY_SENDER, *sender);
        headerdata->put(KEY_TIMESTAMP, timestamp);
        headerdata->put(KEY_MESSAGE_ID, messageId);
        headerdata->put(KEY_NON_REPLAYABLE, nonReplayableId != -1);
        if (nonReplayableId != -1)
            headerdata->put(KEY_NON_REPLAYABLE_ID, nonReplayableId);
        headerdata->put(KEY_RENEWABLE, renewable);
        headerdata->put(KEY_HANDSHAKE, handshake);
        if (capabilities)
            headerdata->put(KEY_CAPABILITIES, dynamic_pointer_cast<MslEncodable>(capabilities));
        if (keyRequestData.size() > 0)
            headerdata->put(KEY_KEY_REQUEST_DATA, MslEncoderUtils::createArray(ctx, format, mslEncodableVector(keyRequestData)));
        if (keyResponseData)
            headerdata->put(KEY_KEY_RESPONSE_DATA, dynamic_pointer_cast<MslEncodable>(keyResponseData));
        if (userAuthData)
            headerdata->put(KEY_USER_AUTHENTICATION_DATA, dynamic_pointer_cast<MslEncodable>(userAuthData));
        if (userIdToken)
            headerdata->put(KEY_USER_ID_TOKEN, dynamic_pointer_cast<MslEncodable>(userIdToken));
        if (serviceTokens.size() > 0)
            headerdata->put(KEY_SERVICE_TOKENS, MslEncoderUtils::createArray(ctx, format, mslEncodableVector(serviceTokens)));
        if (peerMasterToken)
            headerdata->put(KEY_PEER_MASTER_TOKEN, dynamic_pointer_cast<MslEncodable>(peerMasterToken));
        if (peerUserIdToken)
            headerdata->put(KEY_PEER_USER_ID_TOKEN, dynamic_pointer_cast<MslEncodable>(peerUserIdToken));
        if (peerServiceTokens.size() > 0)
            headerdata->put(KEY_PEER_SERVICE_TOKENS, MslEncoderUtils::createArray(ctx, format, mslEncodableVector(peerServiceTokens)));
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_ENCODE_ERROR, "headerdata", e)
            .setMasterToken(masterToken)
            .setEntityAuthenticationData(entityAuthData)
            .setUserIdToken(userIdToken)
            .setUserAuthenticationData(userAuthData)
            .setMessageId(messageId);
    }

    // Create the correct crypto context.
    if (masterToken) {
        // Use a stored master token crypto context if we have one.
        shared_ptr<ICryptoContext> cachedCryptoContext = ctx->getMslStore()->getCryptoContext(masterToken);

        // If there was no stored crypto context try making one from
        // the master token. We can only do this if we can open up the
        // master token.
        if (!cachedCryptoContext) {
            if (!masterToken->isVerified() || !masterToken->isDecrypted())
                throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, masterToken).setUserIdToken(userIdToken).setUserAuthenticationData(userAuthData).setMessageId(messageId);
            messageCryptoContext = make_shared<SessionCryptoContext>(ctx, masterToken);
        } else {
            messageCryptoContext = cachedCryptoContext;
        }
    } else {
        try {
            EntityAuthenticationScheme scheme = entityAuthData->getScheme();
            shared_ptr<EntityAuthenticationFactory> factory = ctx->getEntityAuthenticationFactory(scheme);
            if (!factory)
                throw MslEntityAuthException(MslError::ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
            messageCryptoContext = factory->getCryptoContext(ctx, entityAuthData);
        } catch (MslCryptoException& e) {
            e.setEntityAuthenticationData(entityAuthData);
            e.setUserIdToken(userIdToken);
            e.setUserAuthenticationData(userAuthData);
            e.setMessageId(messageId);
            throw e;
        } catch (MslEntityAuthException& e) {
            e.setEntityAuthenticationData(entityAuthData);
            e.setUserIdToken(userIdToken);
            e.setUserAuthenticationData(userAuthData);
            e.setMessageId(messageId);
            throw e;
        }
    }
}

MessageHeader::MessageHeader(shared_ptr<MslContext> ctx,
		shared_ptr<ByteArray> headerdataBytes,
		shared_ptr<EntityAuthenticationData> ead,
		shared_ptr<MasterToken> mt,
		shared_ptr<ByteArray> signature,
		const map<string, shared_ptr<ICryptoContext>>& cryptoContexts)
{
    shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();

    shared_ptr<ByteArray> plaintext;
    try {
        entityAuthData = (!mt) ? ead : shared_ptr<EntityAuthenticationData>();
        masterToken = mt;
        if (!ead && !mt)
            throw MslMessageException(MslError::MESSAGE_ENTITY_NOT_FOUND);

        // Create the correct crypto context.
        if (mt) {
            // Use a stored master token crypto context if we have one.
            shared_ptr<ICryptoContext> cachedCryptoContext = ctx->getMslStore()->getCryptoContext(mt);

            // If there was no stored crypto context try making one from
            // the master token. We can only do this if we can open up the
            // master token.
            if (!cachedCryptoContext) {
                if (!mt->isVerified() || !mt->isDecrypted())
                    throw MslMasterTokenException(MslError::MASTERTOKEN_UNTRUSTED, mt);
                messageCryptoContext = make_shared<SessionCryptoContext>(ctx, mt);
            } else {
                messageCryptoContext = cachedCryptoContext;
            }
        } else {
            try {
                const EntityAuthenticationScheme scheme = ead->getScheme();
                shared_ptr<EntityAuthenticationFactory> factory = ctx->getEntityAuthenticationFactory(scheme);
                if (!factory)
                    throw MslEntityAuthException(MslError::ENTITYAUTH_FACTORY_NOT_FOUND, scheme.name());
                messageCryptoContext = factory->getCryptoContext(ctx, ead);
            } catch (MslCryptoException& e) {
                e.setEntityAuthenticationData(ead);
                throw e;
            } catch (MslEntityAuthException& e) {
                e.setEntityAuthenticationData(ead);
                throw e;
            }
        }

        // Verify and decrypt the header data.
        //
        // Throw different errors depending on whether or not a master
        // token was used.
        if (!messageCryptoContext->verify(headerdataBytes, signature, encoder)) {
            if (mt)
                throw MslCryptoException(MslError::MESSAGE_MASTERTOKENBASED_VERIFICATION_FAILED);
            else
                throw MslCryptoException(MslError::MESSAGE_ENTITYDATABASED_VERIFICATION_FAILED);
        }
        plaintext = messageCryptoContext->decrypt(headerdataBytes, encoder);
    } catch (MslCryptoException& e) {
        e.setMasterToken(mt);
        e.setEntityAuthenticationData(ead);
        throw e;
    } catch (MslEntityAuthException& e) {
        e.setMasterToken(mt);
        e.setEntityAuthenticationData(ead);
        throw e;
    }

    try {
        headerdata = encoder->parseObject(plaintext);

        // Pull the message ID first because any error responses need to
        // use it.
        messageId = headerdata->getLong(KEY_MESSAGE_ID);
        if (messageId < 0 || messageId > MslConstants::MAX_LONG_VALUE) {
            throw MslMessageException(MslError::MESSAGE_ID_OUT_OF_RANGE, "headerdata " + headerdata->toString()).setMasterToken(mt).setEntityAuthenticationData(ead);
        }
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "headerdata " + *Base64::encode(plaintext), e).setMasterToken(mt).setEntityAuthenticationData(ead);
    }

    try {
        timestamp = (headerdata->has(KEY_TIMESTAMP)) ? headerdata->getLong(KEY_TIMESTAMP) : -1;

        // Pull key response data.
        shared_ptr<MasterToken> tokenVerificationMasterToken;
        if (headerdata->has(KEY_KEY_RESPONSE_DATA)) {
            keyResponseData = KeyResponseData::create(ctx, headerdata->getMslObject(KEY_KEY_RESPONSE_DATA, encoder));

            // The key response data master token is used for token
            // verification in a trusted services network. Otherwise it
            // will be used for peer token verification, which is handled
            // below.
            tokenVerificationMasterToken = (!ctx->isPeerToPeer())
                ? keyResponseData->getMasterToken()
                : mt;
        } else {
            keyResponseData = shared_ptr<KeyResponseData>();
            tokenVerificationMasterToken = mt;
        }

        // User ID tokens are always authenticated by a master token.
        userIdToken = (headerdata->has(KEY_USER_ID_TOKEN))
            ? make_shared<UserIdToken>(ctx, headerdata->getMslObject(KEY_USER_ID_TOKEN, encoder), tokenVerificationMasterToken)
            : shared_ptr<UserIdToken>();
        // Pull user authentication data.
        userAuthData = (headerdata->has(KEY_USER_AUTHENTICATION_DATA))
            ? UserAuthenticationData::create(ctx, tokenVerificationMasterToken, headerdata->getMslObject(KEY_USER_AUTHENTICATION_DATA, encoder))
            : shared_ptr<UserAuthenticationData>();

        // Identify the user if any.
        if (userAuthData) {
            // Reject unencrypted messages containing user authentication data.
            bool encrypted = (masterToken) ? true : entityAuthData->getScheme().encrypts();
            if (!encrypted)
                throw MslMessageException(MslError::UNENCRYPTED_MESSAGE_WITH_USERAUTHDATA).setUserIdToken(userIdToken).setUserAuthenticationData(userAuthData);

            // Verify the user authentication data.
            const UserAuthenticationScheme scheme = userAuthData->getScheme();
            shared_ptr<UserAuthenticationFactory> factory = ctx->getUserAuthenticationFactory(scheme);
            if (!factory)
                throw MslUserAuthException(MslError::USERAUTH_FACTORY_NOT_FOUND, scheme.name()).setUserIdToken(userIdToken).setUserAuthenticationData(userAuthData);
            const string identity = masterToken ? masterToken->getIdentity() : entityAuthData->getIdentity();
            user = factory->authenticate(ctx, identity, userAuthData, userIdToken);
        } else if (userIdToken) {
            user = userIdToken->getUser();
        } else {
            user = shared_ptr<MslUser>();
        }

        // Service tokens are authenticated by the master token if it
        // exists or by the application crypto context.
        set<shared_ptr<ServiceToken>> st;
        if (headerdata->has(KEY_SERVICE_TOKENS)) {
            shared_ptr<MslArray> tokens = headerdata->getMslArray(KEY_SERVICE_TOKENS);
            for (size_t i = 0; i < tokens->size(); ++i) {
                try {
                    shared_ptr<MslObject> serviceTokenMo = tokens->getMslObject((int)i, encoder);
                    shared_ptr<ServiceToken> serviceToken = make_shared<ServiceToken>(ctx, serviceTokenMo, tokenVerificationMasterToken, userIdToken, cryptoContexts);
                    st.insert(serviceToken);
                } catch (MslException& e) {
                    e.setMasterToken(tokenVerificationMasterToken).setUserIdToken(userIdToken).setUserAuthenticationData(userAuthData);
                    MslUtils::rethrow(e);
                }
            }
        }
        serviceTokens = st;
    } catch (const MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "headerdata " + headerdata->toString(), e).setMasterToken(mt).setEntityAuthenticationData(ead).setMessageId(messageId);
    } catch (MslUserAuthException& e) {
        e.setMasterToken(mt);
        e.setEntityAuthenticationData(ead);
        e.setMessageId(messageId);
        throw e;
    } catch (MslException& e) {
        e.setMasterToken(mt);
        e.setEntityAuthenticationData(ead);
        e.setMessageId(messageId);
        MslUtils::rethrow(e);
    }

    try {
        nonReplayableId = (headerdata->has(KEY_NON_REPLAYABLE_ID)) ? headerdata->getLong(KEY_NON_REPLAYABLE_ID) : -1;
        renewable = headerdata->getBoolean(KEY_RENEWABLE);
        // FIXME: Make handshake required once all MSL stacks are updated.
        handshake = (headerdata->has(KEY_HANDSHAKE)) ? headerdata->getBoolean(KEY_HANDSHAKE) : false;

        // Verify values.
        if (nonReplayableId != -1 && (nonReplayableId < 0 || nonReplayableId > MslConstants::MAX_LONG_VALUE))   // FIXME: using -1 for null, but this line also checks < 0?
            throw MslMessageException(MslError::NONREPLAYABLE_ID_OUT_OF_RANGE, "headerdata " + headerdata->toString());

        // Pull message capabilities.
        if (headerdata->has(KEY_CAPABILITIES)) {
            shared_ptr<MslObject> capabilitiesMo = headerdata->getMslObject(KEY_CAPABILITIES, encoder);
            capabilities = make_shared<MessageCapabilities>(capabilitiesMo);
        } else {
            capabilities = shared_ptr<MessageCapabilities>();
        }

        // Pull key request data containers.
        set<shared_ptr<KeyRequestData>> krd;
        if (headerdata->has(KEY_KEY_REQUEST_DATA)) {
            shared_ptr<MslArray> keyRequests = headerdata->getMslArray(KEY_KEY_REQUEST_DATA);
            for (size_t i = 0; i < keyRequests->size(); ++i) {
                krd.insert(KeyRequestData::create(ctx, keyRequests->getMslObject((int)i, encoder)));
            }
        }
        keyRequestData = krd;

        // Only process peer-to-peer tokens if in peer-to-peer mode.
        if (ctx->isPeerToPeer()) {
            // Pull peer master token.
            peerMasterToken = (headerdata->has(KEY_PEER_MASTER_TOKEN))
                ? make_shared<MasterToken>(ctx, headerdata->getMslObject(KEY_PEER_MASTER_TOKEN, encoder))
                : shared_ptr<MasterToken>();
            // The key response data master token is used for peer token
            // verification if in peer-to-peer mode.
            shared_ptr<MasterToken> peerVerificationMasterToken;
            if (keyResponseData)
                peerVerificationMasterToken = keyResponseData->getMasterToken();
            else
                peerVerificationMasterToken = peerMasterToken;

            // Pull peer user ID token. User ID tokens are always
            // authenticated by a master token.
            try {
                peerUserIdToken = (headerdata->has(KEY_PEER_USER_ID_TOKEN))
                    ? make_shared<UserIdToken>(ctx, headerdata->getMslObject(KEY_PEER_USER_ID_TOKEN, encoder), peerVerificationMasterToken)
                    : shared_ptr<UserIdToken>();
            } catch (MslException& e) {
                e.setMasterToken(peerVerificationMasterToken);
                MslUtils::rethrow(e);
            }

            // Peer service tokens are authenticated by the peer master
            // token if it exists or by the application crypto context.
            set<shared_ptr<ServiceToken>> pst;
            if (headerdata->has(KEY_PEER_SERVICE_TOKENS)) {
                shared_ptr<MslArray> tokens = headerdata->getMslArray(KEY_PEER_SERVICE_TOKENS);
                for (size_t i = 0; i < tokens->size(); ++i) {
                    try {
                        shared_ptr<MslObject> serviceTokenMo = tokens->getMslObject((int)i, encoder);
                        pst.insert(make_shared<ServiceToken>(ctx, serviceTokenMo, peerVerificationMasterToken, peerUserIdToken, cryptoContexts));
                    } catch (MslException& e) {
                        e.setMasterToken(peerVerificationMasterToken).setUserIdToken(peerUserIdToken);
                        MslUtils::rethrow(e);
                    }
                }
            }
            peerServiceTokens = pst;
        } else {
            peerMasterToken = shared_ptr<MasterToken>();
            peerUserIdToken = shared_ptr<UserIdToken>();
            peerServiceTokens = set<shared_ptr<ServiceToken>>();
        }
    } catch (MslEncoderException& e) {
        throw MslEncodingException(MslError::MSL_PARSE_ERROR, "headerdata " + headerdata->toString(), e)
            .setMasterToken(mt)
            .setEntityAuthenticationData(ead)
            .setUserIdToken(userIdToken)
            .setUserAuthenticationData(userAuthData)
            .setMessageId(messageId);
    } catch (MslException& e) {
        e.setMasterToken(mt);
        e.setEntityAuthenticationData(ead);
        e.setUserIdToken(userIdToken);
        e.setUserAuthenticationData(userAuthData);
        e.setMessageId(messageId);
        MslUtils::rethrow(e);
    }
}

bool MessageHeader::isEncrypting() const
{
    return masterToken || entityAuthData->getScheme().encrypts();
}

shared_ptr<ICryptoContext> MessageHeader::getCryptoContext() const
{
    return messageCryptoContext;
}

shared_ptr<MslUser> MessageHeader::getUser() const
{
    return user;
}

shared_ptr<EntityAuthenticationData> MessageHeader::getEntityAuthenticationData() const
{
    return entityAuthData;
}

shared_ptr<MasterToken> MessageHeader::getMasterToken() const
{
    return masterToken;
}

shared_ptr<Date> MessageHeader::getTimestamp() const
{
    return (timestamp != -1) ? make_shared<Date>(timestamp * MILLISECONDS_PER_SECOND) : shared_ptr<Date>();
}

int64_t MessageHeader::getMessageId() const
{
    return messageId;
}

int64_t MessageHeader::getNonReplayableId() const
{
    return nonReplayableId;
}

bool MessageHeader::isRenewable() const
{
    return renewable;
}

bool MessageHeader::isHandshake() const
{
    return handshake;
}

shared_ptr<MessageCapabilities> MessageHeader::getMessageCapabilities() const
{
    return capabilities;
}

set<shared_ptr<KeyRequestData>> MessageHeader::getKeyRequestData() const
{
    return keyRequestData;
}

shared_ptr<KeyResponseData> MessageHeader::getKeyResponseData() const
{
    return keyResponseData;
}

shared_ptr<userauth::UserAuthenticationData> MessageHeader::getUserAuthenticationData() const
{
    return userAuthData;
}

shared_ptr<UserIdToken> MessageHeader::getUserIdToken() const
{
    return userIdToken;
}

set<shared_ptr<ServiceToken>> MessageHeader::getServiceTokens() const
{
    return serviceTokens;
}

shared_ptr<MasterToken> MessageHeader::getPeerMasterToken() const
{
    return peerMasterToken;
}

shared_ptr<UserIdToken> MessageHeader::getPeerUserIdToken() const
{
    return peerUserIdToken;
}

set<shared_ptr<ServiceToken>> MessageHeader::getPeerServiceTokens() const
{
    return peerServiceTokens;
}

shared_ptr<ByteArray> MessageHeader::toMslEncoding(shared_ptr<io::MslEncoderFactory> encoder, const io::MslEncoderFormat& format) const
{
    // Return any cached encoding.
    std::map<io::MslEncoderFormat, shared_ptr<ByteArray>>::const_iterator it = encodings.find(format);
    if (it != encodings.end())
        return it->second;

    // Encrypt and sign the header data.
    shared_ptr<ByteArray> plaintext = encoder->encodeObject(headerdata, format);
    shared_ptr<ByteArray> ciphertext;
    try {
        ciphertext = messageCryptoContext->encrypt(plaintext, encoder, format);
    } catch (const MslCryptoException& e) {
        throw MslEncoderException("Error encrypting the header data.", e);
    }
    shared_ptr<ByteArray> signature;
    try {
        signature = messageCryptoContext->sign(ciphertext, encoder, format);
    } catch (const MslCryptoException& e) {
        throw MslEncoderException("Error signging the header data.", e);
    }

    // Create the encoding.
    shared_ptr<MslObject> header = encoder->createObject();
    if (masterToken)
        header->put<shared_ptr<MslEncodable>>(HeaderKeys::KEY_MASTER_TOKEN, masterToken);
    else
        header->put<shared_ptr<MslEncodable>>(HeaderKeys::KEY_ENTITY_AUTHENTICATION_DATA, entityAuthData);
    header->put(HeaderKeys::KEY_HEADERDATA, ciphertext);
    header->put(HeaderKeys::KEY_SIGNATURE, signature);
    shared_ptr<ByteArray> encoding = encoder->encodeObject(header, format);

    // Cache and return the encoding.
    encodings.insert(make_pair(format, encoding));
    return encoding;
}

namespace {

// Compare two sets of shared_ptrs of type T. Since the sets are effectively
// unsorted (they are sorted by pointer value), and the elements must be
// dereferenced before comparison, we are effectively forced to use O(n^2)
// search.
template <typename T>
bool sharedPtrSetEq(const set<shared_ptr<T>>& s1, const set<shared_ptr<T>>& s2)
{
    if (s1.size() != s2.size())
        return false;
    // std::sets do not have duplicates, so if we find that one set contains all
    // the elements of the other, the sets can be viewed as matching.
    size_t matchCount = 0;
    typename set<shared_ptr<T>>::const_iterator it, jt;
    for (it = s1.begin(); it != s1.end(); ++it)
        for (jt = s2.begin(); jt != s2.end(); ++jt)
            if (**it == **jt) ++matchCount;
    return matchCount == s1.size();
}

} //namespace anonymous

bool MessageHeader::equals(shared_ptr<const Header> obj) const
{
    if (!obj) return false;
    if (this == obj.get()) return true;
    if (!instanceof<const MessageHeader>(obj)) return false;
    shared_ptr<const MessageHeader> that = dynamic_pointer_cast<const MessageHeader>(obj);
	return ((masterToken && masterToken->equals(that->masterToken)) ||
			(entityAuthData && entityAuthData->equals(that->entityAuthData))) &&
			(timestamp == that->timestamp) &&
			(messageId == that->messageId) &&
			(nonReplayableId == that->nonReplayableId) &&
			(renewable == that->renewable) &&
			(handshake == that->handshake) &&
			(MslUtils::sharedPtrCompare(capabilities, that->capabilities)) &&
			(sharedPtrSetEq(keyRequestData, that->keyRequestData)) &&
			(MslUtils::sharedPtrCompare(keyResponseData, that->keyResponseData)) &&
			(MslUtils::sharedPtrCompare(userAuthData, that->userAuthData)) &&
			(MslUtils::sharedPtrCompare(userIdToken, that->userIdToken)) &&
			(sharedPtrSetEq(serviceTokens, that->serviceTokens)) &&
			(MslUtils::sharedPtrCompare(peerMasterToken, that->peerMasterToken)) &&
			(MslUtils::sharedPtrCompare(peerUserIdToken, that->peerUserIdToken)) &&
			(sharedPtrSetEq(peerServiceTokens, that->peerServiceTokens));
}

bool operator==(const MessageHeader& a, const MessageHeader& b)
{
	shared_ptr<const MessageHeader> ap(&a, &MslUtils::nullDeleter<MessageHeader>);
	shared_ptr<const MessageHeader> bp(&b, &MslUtils::nullDeleter<MessageHeader>);
	return ap->equals(bp);
}

ostream& operator<<(ostream& os, const MessageHeader& /*header*/)
{
	// FIXME
	return os << "MessageHeader placeholder";
}

ostream& operator<<(ostream& os, shared_ptr<MessageHeader> header)
{
	return os << *header;
}

}}} // namespace netflix::msl::msg
