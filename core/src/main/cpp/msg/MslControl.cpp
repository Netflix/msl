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

// Note: C++11 is allowed in this file

#include <msg/MslControl.h>
#include <crypto/JcaAlgorithm.h>
#include <crypto/Key.h>
#include <crypto/NullCryptoContext.h>
#include <crypto/Random.h>
#include <entityauth/EntityAuthenticationFactory.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <entityauth/UnauthenticatedAuthenticationData.h>
#include <io/InputStream.h>
#include <io/MslEncoderFactory.h>
#include <io/OutputStream.h>
#include <io/Url.h>
#include <IllegalStateException.h>
#include <IOException.h>
#include <keyx/KeyExchangeFactory.h>
#include <keyx/KeyExchangeScheme.h>
#include <keyx/KeyRequestData.h>
#include <msg/ErrorHeader.h>
#include <msg/ErrorMessageRegistry.h>
#include <msg/FilterStreamFactory.h>
#include <msg/MessageBuilder.h>
#include <msg/MessageCapabilities.h>
#include <msg/MessageContext.h>
#include <msg/MessageDebugContext.h>
#include <msg/MessageHeader.h>
#include <msg/MessageInputStream.h>
#include <msg/MessageOutputStream.h>
#include <msg/MessageServiceTokenBuilder.h>
#include <msg/MessageFactory.h>
#include <msg/PayloadChunk.h>
#include <tokens/MslUser.h>
#include <tokens/TokenFactory.h>
#include <userauth/UserAuthenticationData.h>
#include <userauth/UserAuthenticationFactory.h>
#include <userauth/UserAuthenticationScheme.h>
#include <util/Executor.h>
#include <util/MslContext.h>
#include <util/MslUtils.h>
#include <util/SimpleMslStore.h>
#include <MslConstants.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslErrorResponseException.h>
#include <MslInternalException.h>
#include <MslMessageException.h>
#include <iostream>
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <sys/time.h>
#include <tokens/ServiceToken.h>
#include <tokens/UserIdToken.h>
#include <TimeoutException.h>
#include <util/ReadWriteLock.h>

using namespace std;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::io;
using namespace netflix::msl::keyx;
using namespace netflix::msl::msg;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;
using namespace netflix::msl::util;

namespace netflix {
namespace msl {
namespace msg {

namespace {

/**
 * A dummy MSL context only used for our dummy
 * {@link MslControl#NULL_MASTER_TOKEN}.
 */
class DummyMslContext : public MslContext
{
private:
    class DummyMslEncoderFactory : public MslEncoderFactory
    {
    public:
        virtual ~DummyMslEncoderFactory() {}
        DummyMslEncoderFactory() {}

        /** @inheritDoc */
        virtual MslEncoderFormat getPreferredFormat(const std::set<MslEncoderFormat>& /*formats = std::set<MslEncoderFormat>()*/) {
            return MslEncoderFormat::JSON;
        }

    protected:
        /** @inheritDoc */
        virtual std::shared_ptr<MslTokenizer> generateTokenizer(std::shared_ptr<InputStream> /*source*/, const MslEncoderFormat& /*format*/) {
            throw MslInternalException("DummyMslEncoderFactory.createTokenizer() not supported.");
        }

    public:
        /** @inheritDoc */
        virtual std::shared_ptr<MslObject> parseObject(std::shared_ptr<ByteArray> /*encoding*/) {
            throw MslInternalException("DummyMslEncoderFactory.parseObject() not supported.");
        }

        /** @inheritDoc */
        virtual std::shared_ptr<ByteArray> encodeObject(std::shared_ptr<MslObject> /*object*/, const MslEncoderFormat& /*format*/) {
            throw MslInternalException("DummyMslEncoderFactory.encodeObject() not supported.");
        }
    };

public:
    virtual ~DummyMslContext() {}
    DummyMslContext()
    : random(make_shared<Random>())
    , entityAuthData(make_shared<UnauthenticatedAuthenticationData>("dummy"))
    , mslCryptoContext(make_shared<NullCryptoContext>())
    , store(make_shared<SimpleMslStore>())
    , encoderFactory(make_shared<DummyMslEncoderFactory>())
    {}
    /** @inheritDoc */
    virtual int64_t getTime() override {
        struct timeval tp;
        gettimeofday(&tp, NULL);
        uint64_t ms = static_cast<uint64_t>(tp.tv_sec) * 1000ull + static_cast<uint64_t>(tp.tv_usec) / 1000ull;
        return static_cast<int64_t>(ms);
    }
    /** @inheritDoc */
    virtual shared_ptr<IRandom> getRandom() override { return random; }
    /** @inheritDoc */
    virtual bool isPeerToPeer() override { return false; }
    /** @inheritDoc */
    virtual shared_ptr<MessageCapabilities> getMessageCapabilities() override {
        return nullptr;
    }
    /** @inheritDoc */
    virtual shared_ptr<EntityAuthenticationData> getEntityAuthenticationData(const ReauthCode&) override {
        return entityAuthData;
    }
    /** @inheritDoc */
    virtual shared_ptr<ICryptoContext> getMslCryptoContext() override { return mslCryptoContext; }
    /** @inheritDoc */
    virtual EntityAuthenticationScheme getEntityAuthenticationScheme(const string& name) override {
        return EntityAuthenticationScheme::getScheme(name);
    }
    /** @inheritDoc */
    virtual shared_ptr<EntityAuthenticationFactory> getEntityAuthenticationFactory(const EntityAuthenticationScheme&) override {
        return nullptr;
    }
    /** @inheritDoc */
    virtual UserAuthenticationScheme getUserAuthenticationScheme(const string& name) override {
        return UserAuthenticationScheme::getScheme(name);
    }
    /** @inheritDoc */
    virtual shared_ptr<UserAuthenticationFactory> getUserAuthenticationFactory(const UserAuthenticationScheme&) override {
        return shared_ptr<userauth::UserAuthenticationFactory>();
    }
    /** @inheritDoc */
    virtual shared_ptr<TokenFactory> getTokenFactory() override {
        throw MslInternalException("Dummy token factory should never actually get used.");
    }
    /** @inheritDoc */
    virtual KeyExchangeScheme getKeyExchangeScheme(const string& name) override {
        return KeyExchangeScheme::getScheme(name);
    }
    /** @inheritDoc */
    virtual shared_ptr<KeyExchangeFactory> getKeyExchangeFactory(const KeyExchangeScheme&) override {
        return nullptr;
    }
    /** @inheritDoc */
    virtual set<shared_ptr<KeyExchangeFactory>> getKeyExchangeFactories() override {
        return keyxFactories;
    }
    /** @inheritDoc */
    virtual shared_ptr<MslStore> getMslStore() override { return store; }
    /** @inheritDoc */
    virtual shared_ptr<MslEncoderFactory> getMslEncoderFactory() override { return encoderFactory; }
private:
    shared_ptr<IRandom> random;
    shared_ptr<EntityAuthenticationData> entityAuthData;
    shared_ptr<ICryptoContext> mslCryptoContext;
    set<shared_ptr<KeyExchangeFactory>> keyxFactories;
    shared_ptr<MslStore> store;
    shared_ptr<MslEncoderFactory> encoderFactory;
};

/**
 * A dummy error message registry that always returns null for the user
 * message.
 */
class DummyMessageRegistry : public ErrorMessageRegistry
{
public:
    virtual ~DummyMessageRegistry() {}
    /** @inheritDoc */
    virtual string getUserMessage(const MslError&, const vector<string>&) override
    {
        return string();
    }
    /** @inheritDoc */
    virtual string getUserMessage(const IException&, const vector<string>&) override
    {
        return string();
    }
};

/**
 * Base class for custom message contexts. All methods are passed through
 * to the backing message context.
 */
class FilterMessageContext : public MessageContext
{
public:
    /** @inheritDoc */
    virtual map<string, shared_ptr<ICryptoContext>> getCryptoContexts() override {
        return appCtx->getCryptoContexts();
    }
    /** @inheritDoc */
    virtual string getRemoteEntityIdentity() override { return appCtx->getRemoteEntityIdentity(); }
    /** @inheritDoc */
    virtual bool isEncrypted() override { return appCtx->isEncrypted(); }
    /** @inheritDoc */
    virtual bool isIntegrityProtected() override { return appCtx->isIntegrityProtected(); }
    /** @inheritDoc */
    virtual bool isNonReplayable() override { return appCtx->isNonReplayable(); }
    /** @inheritDoc */
    virtual bool isRequestingTokens() override { return appCtx->isRequestingTokens(); }
    /** @inheritDoc */
    virtual string  getUserId() override { return appCtx->getUserId(); }
    /** @inheritDoc */
    virtual shared_ptr<UserAuthenticationData> getUserAuthData(const ReauthCode& reauthCode, bool renewable, bool required) override {
        return appCtx->getUserAuthData(reauthCode, renewable, required);
    }
    /** @inheritDoc */
    virtual shared_ptr<MslUser> getUser() override { return appCtx->getUser(); }
    /** @inheritDoc */
    virtual set<shared_ptr<KeyRequestData>> getKeyRequestData() override {
        return appCtx->getKeyRequestData();
    }
    /** @inheritDoc */
    virtual void updateServiceTokens(shared_ptr<MessageServiceTokenBuilder> builder, bool handshake) override {
        appCtx->updateServiceTokens(builder, handshake);
    }
    /** @inheritDoc */
    virtual void write(shared_ptr<MessageOutputStream> output) override {
        appCtx->write(output);
    }
    /** @inheritDoc */
    virtual shared_ptr<MessageDebugContext> getDebugContext() override {
        return appCtx->getDebugContext();
    }
protected:
    virtual ~FilterMessageContext() {}
    /**
     * Creates a message context that passes through calls to the backing
     * message context.
     *
     * @param appCtx the application's message context.
     */
    FilterMessageContext(shared_ptr<MessageContext> appCtx) : appCtx(appCtx) {}
    /** The backing application message context. */
    shared_ptr<MessageContext> appCtx;
private:
    FilterMessageContext() = delete;
};

/**
 * This message context is used to re-send a message.
 */
class ResendMessageContext : public FilterMessageContext
{
public:
    virtual ~ResendMessageContext() {}
    /**
     * Creates a message context used to re-send a message after an error
     * or handshake. If the payloads are empty the application's message
     * context will be asked to write its data. Otherwise the provided
     * payloads will be used for the message's application data.
     *
     * @param payloads original request payload chunks. May be null.
     * @param appCtx the application's message context.
     */
    ResendMessageContext(vector<shared_ptr<PayloadChunk>> payloads, shared_ptr<MessageContext> appCtx)
    : FilterMessageContext(appCtx), payloads(payloads)
    {
    }
    /** @inheritDoc */
    virtual void write(shared_ptr<MessageOutputStream> output) override
    {
        // If there are no payloads, ask the application message context to
        // write its data.
        if (payloads.empty())
        {
            appCtx->write(output);
            return;
        }

        // Rewrite the payloads one-by-one.
        for (auto chunk : payloads) {
            output->setCompressionAlgorithm(chunk->getCompressionAlgo());
            output->write(*chunk->getData());
            if (chunk->isEndOfMessage())
                output->close();
            else
                output->flush();
        }
    }
private:
    ResendMessageContext() = delete;
    /** The application data to resend. */
    vector<shared_ptr<PayloadChunk>> payloads;
};

/**
 * This message context is used to send messages that will not expect a
 * response.
 */
class SendMessageContext : public FilterMessageContext
{
public:
    virtual ~SendMessageContext() {}

    /**
     * Creates a message context used to send messages that do not expect a
     * response by ensuring that the message context conforms to those
     * expectations.
     *
     * @param appCtx the application's message context.
     */
    SendMessageContext(shared_ptr<MessageContext> appCtx)
        : FilterMessageContext(appCtx)
    {}

    /** @inheritDoc */
    virtual bool isRequestingTokens() override { return false; }
};

/**
 * This message context is used to send a handshake response.
 */
class KeyxResponseMessageContext : public FilterMessageContext
{
public:
    virtual ~KeyxResponseMessageContext() {}

    /**
     * Creates a message context used for automatically generated handshake
     * responses.
     *
     * @param appCtx the application's message context.
     */
    KeyxResponseMessageContext(shared_ptr<MessageContext> appCtx)
        : FilterMessageContext(appCtx)
    {}

    /** @inheritDoc */
    virtual bool isEncrypted() override {
        // Key exchange responses cannot require encryption otherwise key
        // exchange could never succeed in some cases.
        return false;
    }

    /** @inheritDoc */
    virtual bool isIntegrityProtected() override {
        // Key exchange responses cannot require integrity protection
        // otherwise key exchange could never succeed in some cases.
        return false;
    }

    /** @inheritDoc */
    virtual bool isNonReplayable() override { return false; }

    /** @inheritDoc */
    virtual void write(shared_ptr<MessageOutputStream>) override {
        // No application data.
    }

private:
    KeyxResponseMessageContext() = delete;
};

/**
 * Update the MSL store by removing any service tokens marked for deletion
 * and adding/replacing any other service tokens contained in the message
 * header->
 *
 * @param ctx MSL context.
 * @param masterToken master for the service tokens.
 * @param userIdToken user ID token for the service tokens.
 * @param serviceTokens the service tokens to update.
 * @throws MslException if a token cannot be removed or added/replaced
 *         because of a master token or user ID token mismatch.
 */
void storeServiceTokens(shared_ptr<MslContext> ctx, shared_ptr<MasterToken> masterToken,
        shared_ptr<UserIdToken> userIdToken, const set<shared_ptr<ServiceToken>>& serviceTokens)
{
    // Remove deleted service tokens from the store-> Update stored
    // service tokens.
    shared_ptr<MslStore> store = ctx->getMslStore();
    set<shared_ptr<ServiceToken>> storeTokens;
    for (auto token : serviceTokens) {
        // Skip service tokens that are bound to a master token if the
        // local entity issued the master token.
        if (token->isBoundTo(masterToken) && masterToken->isVerified())
            continue;
        shared_ptr<ByteArray> data = token->getData();
        if (data && data->empty()) {
            // FIXME: need shared_ptr<string> for removeServiceTokens
            shared_ptr<string> tokenName = make_shared<string>(token->getName());
            store->removeServiceTokens(tokenName,
                    token->isMasterTokenBound() ? masterToken : nullptr,
                    token->isUserIdTokenBound() ? userIdToken : nullptr);
        } else {
            storeTokens.insert(token);
        }
    }
    store->addServiceTokens(storeTokens);
}

/**
 * Common base class for thread-callable classes
 */
template <typename T>
struct Callable
{
    virtual ~Callable() {}
    Callable(MslControl *mslControl, shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx)
    : mslControl(mslControl), ctx(ctx), msgCtx(msgCtx) {}
    virtual T operator()() = 0;
    MslControl * const mslControl;
    /** MSL context. */
    shared_ptr<MslContext> ctx;
    /** Message context. */
    shared_ptr<MessageContext> msgCtx;
};

} // namespace anonymous

struct MslControl::ErrorResult
{
    /**
     * Create a new result with the provided request builder and message
     * context.
     *
     * @param builder
     * @param msgCtx
     */
    ErrorResult(shared_ptr<MessageBuilder> builder, shared_ptr<MessageContext> msgCtx)
    : builder(builder), msgCtx(msgCtx) {}
    /** The new request to send. */
    shared_ptr<MessageBuilder> builder;
    /** The new message context to use. */
    shared_ptr<MessageContext> msgCtx;
};

struct MslControl::SendResult
{
    virtual ~SendResult() {}
    /**
     * Create a new result with the provided message output stream
     * containing the cached application data (which was not sent if the
     * message was a handshake).
     *
     * @param request request message output stream.
     * @param handshake true if a handshake message was sent and the
     *        application data was not sent.
     */
    SendResult(shared_ptr<MessageOutputStream> request, bool handshake)
    : request(request), handshake(handshake) {}
    /** The request message output stream. */
    shared_ptr<MessageOutputStream> request;
    /** True if the message was a handshake (application data was not sent). */
    bool handshake;
};

/**
 * The result of sending and receiving messages.
 */
struct MslControl::SendReceiveResult : MslControl::SendResult
{
    /**
     * Create a new result with the provided response and send result.
     *
     * @param response response message input stream.
     * @param sent sent message result.
     */
    SendReceiveResult(shared_ptr<MessageInputStream> response, shared_ptr<MslControl::SendResult> sent)
    : SendResult(sent->request, sent->handshake), response(response) {}
    /** The response message input stream. */
    shared_ptr<MessageInputStream> response;
};



/**
 * A map key based off a MSL context and master token pair.
 */
class MslContextMasterTokenKey
{
public:
    /**
     * Create a new MSL context and master token map key.
     *
     * @param ctx MSL context.
     * @param masterToken master token.
     */
    MslContextMasterTokenKey(shared_ptr<MslContext> ctx, shared_ptr<MasterToken> masterToken)
    : ctx(ctx), masterToken(masterToken)
    {
    }

    bool equals(shared_ptr<MslContextMasterTokenKey> that)
    {
        if (this == that.get()) return true;
        return ctx->equals(that->ctx) && masterToken->equals(that->masterToken);
    }
private:
    MslContextMasterTokenKey() = delete;
    /** MSL context. */
    shared_ptr<MslContext> ctx;
    /** Master token. */
    shared_ptr<MasterToken> masterToken;
};

MslChannel::MslChannel(shared_ptr<MessageInputStream> input, shared_ptr<MessageOutputStream> output) : input_(input) , output_(output) {}
shared_ptr<MessageInputStream> MslChannel::input() { return input_; }
shared_ptr<MessageOutputStream> MslChannel::output() { return output_; }
            
MslControl::MslControl(int32_t numThreads)
{
    init(numThreads);
}

MslControl::MslControl(int32_t numThreads, shared_ptr<MessageFactory> messageFactory, shared_ptr<ErrorMessageRegistry> messageRegistry)
: messageFactory(messageFactory)
, messageRegistry(messageRegistry)
{
    init(numThreads);
}

void MslControl::init(int32_t numThreads)
{
    if (numThreads < 0)
        throw IllegalArgumentException("Number of threads must be non-negative.");
    if (numThreads)
        executor = make_shared<AsynchronousExecutor>();
    else
        executor = make_shared<SynchronousExecutor>();

    // Create the dummy master token used as a special value when releasing
    // the renewal lock without a new master token.
    try {
        shared_ptr<MslContext> ctx(make_shared<DummyMslContext>());
        shared_ptr<MslObject> dummy = ctx->getMslEncoderFactory()->createObject();
        shared_ptr<ByteArray> keydata = make_shared<ByteArray>(16);
        ctx->getRandom()->nextBytes(*keydata);
        const SecretKey encryptionKey(keydata, JcaAlgorithm::AES);
        const SecretKey hmacKey(keydata, JcaAlgorithm::HMAC_SHA256);
        NULL_MASTER_TOKEN = make_shared<MasterToken>(ctx, Date::now(), Date::now(), 1L, 1L, dummy, "dummy", encryptionKey, hmacKey);
    } catch (const MslEncodingException& e) {
        throw MslInternalException("Unexpected exception when constructing dummy master token.", e);
    } catch (const MslCryptoException& e) {
        throw MslInternalException("Unexpected exception when constructing dummy master token.", e);
    }

}

void MslControl::setFilterFactory(shared_ptr<FilterStreamFactory> factory)
{
    filterFactory = factory;
}
                
void MslControl::shutdown()
{
    executor->shutdown();
}

shared_ptr<MasterToken> MslControl::getNewestMasterToken(shared_ptr<MslContext> ctx)
{
    // FIXME: This can get stuck forever if there's no way to interrupt/abort.
    do {
        // Get the newest master token. If there is none then immediately
        // return.
        shared_ptr<MslStore> store = ctx->getMslStore();
        shared_ptr<MasterToken> masterToken = store->getMasterToken();
        if (!masterToken) return nullptr;

        // Acquire the master token read lock, creating it if necessary.
        shared_ptr<MslContextMasterTokenKey> key = make_shared<MslContextMasterTokenKey>(ctx, masterToken);
        shared_ptr<ReadWriteLock> newLock = make_shared<ReadWriteLock>();
        shared_ptr<ReadWriteLock> oldLock = masterTokenLocks.putIfAbsent(key, newLock);
        shared_ptr<ReadWriteLock> finalLock = (oldLock) ? oldLock : newLock;
        finalLock->readLock();

        // Now we have to be tricky and make sure the master token we just
        // acquired is still the newest master token. This is necessary
        // just in case the master token was deleted between grabbing it
        // from the MSL store and acquiring the read lock.
        shared_ptr<MasterToken> newestMasterToken = store->getMasterToken();
        if (masterToken->equals(newestMasterToken))
            return masterToken;

        // If the master tokens are not the same then release the read
        // lock, acquire the write lock, and then delete the master token
        // lock (it may already be deleted). Then try again->
        finalLock->unlock();
        finalLock->writeLock();
        masterTokenLocks.remove(key);
        finalLock->unlock();
    } while (true);
}

void MslControl::deleteMasterToken(shared_ptr<MslContext> ctx, shared_ptr<MasterToken> masterToken)
{
    // Do nothing if the master token is null.
    if (!masterToken)
        return;

    // Acquire the write lock and delete the master token from the store->
    //
    // TODO it would be nice to do this on another thread to avoid delaying
    // the application.
    shared_ptr<MslContextMasterTokenKey> key = make_shared<MslContextMasterTokenKey>(ctx, masterToken);
    shared_ptr<ReadWriteLock> newLock = make_shared<ReadWriteLock>();
    shared_ptr<ReadWriteLock> oldLock = masterTokenLocks.putIfAbsent(key, newLock);

    // ReentrantReadWriteLock requires us to release the read lock if
    // we are holding it before acquiring the write lock. If there is
    // an old lock then we are already holding the read lock. Otherwise
    // no one is holding any locks.
    // FIXME: warning - java code separates out the old lock into separate read and write locks
    shared_ptr<ReadWriteLock> writeLock;
    if (!oldLock) {
        oldLock->unlock();
        writeLock = oldLock;
    } else {
        writeLock = newLock;
    }
    writeLock->writeLock();

    // It should be okay to delete this read/write lock because no
    // one should be using the deleted master token anymore; a new
    // master token would have been received before deleting the
    // old one.
    // We want to make sure we do this even if removeCryptoContext() below
    // throws, so we have to make an RAII object.
    class Cleanup
    {
    public:
        Cleanup(ConcurrentHashMap<MslContextMasterTokenKey, ReadWriteLock>& masterTokenLocks,
            shared_ptr<ReadWriteLock>& writeLock, shared_ptr<MslContextMasterTokenKey>& key)
        : masterTokenLocks(masterTokenLocks), writeLock(writeLock), key(key) {}
        ~Cleanup() {
            masterTokenLocks.remove(key);
            writeLock->unlock();
        }
    private:
        ConcurrentHashMap<MslContextMasterTokenKey, ReadWriteLock>& masterTokenLocks;
        shared_ptr<ReadWriteLock>& writeLock;
        shared_ptr<MslContextMasterTokenKey>& key;
    };
    Cleanup cleanup(masterTokenLocks, writeLock, key);
    ctx->getMslStore()->removeCryptoContext(masterToken);
}

void MslControl::releaseMasterToken(shared_ptr<MslContext> ctx, shared_ptr<MasterToken> masterToken)
{
    if (masterToken) {
        shared_ptr<MslContextMasterTokenKey> key = make_shared<MslContextMasterTokenKey>(ctx, masterToken);
        shared_ptr<ReadWriteLock> lock = masterTokenLocks.get(key);

        // The lock may be null if the master token was deleted.
        if (lock)
            lock->unlock();
    }
}

void MslControl::updateCryptoContexts(shared_ptr<MslContext> ctx,
        shared_ptr<MessageHeader> messageHeader,
        shared_ptr<KeyExchangeFactory::KeyExchangeFactory::KeyExchangeData> keyExchangeData)
{
    // In trusted network mode save the crypto context of the message's key
    // response data as an optimization.
    shared_ptr<MslStore> store = ctx->getMslStore();
    if (!ctx->isPeerToPeer() && keyExchangeData) {
        shared_ptr<KeyResponseData> keyResponseData = keyExchangeData->keyResponseData;
        shared_ptr<ICryptoContext> keyxCryptoContext = keyExchangeData->cryptoContext;
        shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
        store->setCryptoContext(keyxMasterToken, keyxCryptoContext);

        // Delete the old master token. Even if we receive future messages
        // with this master token we can reconstruct the crypto context.
        deleteMasterToken(ctx, messageHeader->getMasterToken());
    }
}

void MslControl::updateCryptoContexts(shared_ptr<MslContext> ctx, shared_ptr<MessageHeader> request,
        shared_ptr<MessageInputStream> response)
{
    // Do nothing for error messages.
    shared_ptr<MessageHeader> messageHeader = response->getMessageHeader();
    if (!messageHeader)
        return;

    // Save the crypto context of the message's key response data.
    shared_ptr<MslStore> store = ctx->getMslStore();
    shared_ptr<KeyResponseData> keyResponseData = messageHeader->getKeyResponseData();
    if (keyResponseData) {
        shared_ptr<MasterToken> keyxMasterToken = keyResponseData->getMasterToken();
        store->setCryptoContext(keyxMasterToken, response->getKeyExchangeCryptoContext());

        // Delete the old master token. We won't use it anymore to build
        // messages.
        deleteMasterToken(ctx, request->getMasterToken());
    }
}

shared_ptr<MessageBuilder> MslControl::buildRequest(shared_ptr<MslContext> ctx,
        shared_ptr<MessageContext> msgCtx)
{
    shared_ptr<MslStore> store = ctx->getMslStore();

    // Grab the newest master token.
    shared_ptr<MasterToken> masterToken = getNewestMasterToken(ctx);
    try {
        shared_ptr<UserIdToken> userIdToken;
        if (masterToken) {
            // Grab the user ID token for the message's user. It may not be bound
            // to the newest master token if the newest master token invalidated
            // it.
            const string userId = msgCtx->getUserId();
            shared_ptr<UserIdToken> storedUserIdToken = (!userId.empty()) ? store->getUserIdToken(userId) : nullptr;
            userIdToken = (storedUserIdToken && storedUserIdToken->isBoundTo(masterToken)) ? storedUserIdToken : nullptr;
        } else {
            userIdToken = nullptr;
        }

        shared_ptr<MessageBuilder> builder = messageFactory->createRequest(ctx, masterToken, userIdToken);
        builder->setNonReplayable(msgCtx->isNonReplayable());
        return builder;
    } catch (const MslException& e) {
        // Release the master token lock.
        releaseMasterToken(ctx, masterToken);
        throw MslInternalException("User ID token not bound to master token despite internal check.", e);
    } catch (...) {
        // Release the master token lock.
        releaseMasterToken(ctx, masterToken);
        throw;
    }
}

shared_ptr<MessageBuilder> MslControl::buildResponse(shared_ptr<MslContext> ctx,
        shared_ptr<MessageContext> msgCtx, shared_ptr<MessageHeader> request)
{
    // Create the response->
    shared_ptr<MessageBuilder> builder = messageFactory->createResponse(ctx, request);
    builder->setNonReplayable(msgCtx->isNonReplayable());

    // Trusted network clients should use the newest master token. Trusted
    // network servers must not use a newer master token. This method is
    // only called by trusted network clients after a handshake response is
    // received so if the request does not contain key response data then
    // we know the local entity is a trusted network server and should
    // return immediately.
    if (!ctx->isPeerToPeer() && request->getKeyResponseData())
        return builder;

    // In peer-to-peer mode the primary master token may no longer be known
    // if it was renewed between calls to receive() and respond()
    // (otherwise we would have held a lock). In this case, we need to
    // use the newest primary authentication tokens.
    //
    // Likewise, if the primary authentication tokens are not already set
    // then use what we have received.
    //
    // Either way we should be able to use the newest master token,
    // acquiring the read lock at the same time which we definitely want.
    shared_ptr<MasterToken> masterToken = getNewestMasterToken(ctx);
    try {
        shared_ptr<UserIdToken> userIdToken;
        if (masterToken) {
            // Grab the user ID token for the message's user. It may not be
            // bound to the newest master token if the newest master token
            // invalidated it.
            const string userId = msgCtx->getUserId();
            shared_ptr<MslStore> store = ctx->getMslStore();
            shared_ptr<UserIdToken> storedUserIdToken = (!userId.empty()) ? store->getUserIdToken(userId) : nullptr;
            userIdToken = (storedUserIdToken && storedUserIdToken->isBoundTo(masterToken)) ? storedUserIdToken : nullptr;
        } else {
            userIdToken = nullptr;
        }

        // Set the authentication tokens.
        builder->setAuthTokens(masterToken, userIdToken);
        return builder;
    } catch (...) {
        // Release the master token lock.
        releaseMasterToken(ctx, masterToken);
        throw;
    }
}

shared_ptr<MessageBuilder> MslControl::buildDetachedResponse(shared_ptr<MslContext> ctx,
        shared_ptr<MessageContext> msgCtx,
        shared_ptr<MessageHeader> request)
{
    // Create an idempotent response. Assign a random message ID.
    shared_ptr<MessageBuilder> builder = messageFactory->createIdempotentResponse(ctx, request);
    builder->setNonReplayable(msgCtx->isNonReplayable());
    builder->setMessageId(MslUtils::getRandomLong(ctx));
    return builder;
}

shared_ptr<MslControl::ErrorResult> MslControl::buildErrorResponse(shared_ptr<MslContext> ctx,
        shared_ptr<MessageContext> msgCtx, shared_ptr<MslControl::SendResult> sent,
        shared_ptr<ErrorHeader> errorHeader)
{
    // Handle the error.
    shared_ptr<MessageHeader> requestHeader = sent->request->getMessageHeader();
    const vector<shared_ptr<PayloadChunk>> payloads = sent->request->getPayloads();
    const MslConstants::ResponseCode errorCode = errorHeader->getErrorCode();
    switch (errorCode) {
        case MslConstants::ResponseCode::entitydataReauth:
        case MslConstants::ResponseCode::entityReauth:
        {
            // If the MSL context cannot provide new entity authentication
            // data then return null. This function should never return
            // null.
            try {
                const MslContext::ReauthCode reauthCode = MslContext::ReauthCode::valueOf(errorCode);
                if (!ctx->getEntityAuthenticationData(reauthCode))
                    return shared_ptr<MslControl::ErrorResult>();
            } catch (const IllegalArgumentException& e) {
                throw MslInternalException("Unsupported response code mapping onto entity re-authentication codes.", e);
            }

            // Resend the request without a master token or user ID token.
            // Make sure the use the error header message ID + 1.
            const int64_t messageId = MessageBuilder::incrementMessageId(errorHeader->getMessageId());
            shared_ptr<MessageContext> resendMsgCtx = make_shared<ResendMessageContext>(payloads, msgCtx);
            shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, nullptr, nullptr, messageId);
            if (ctx->isPeerToPeer()) {
                shared_ptr<MasterToken> peerMasterToken = requestHeader->getPeerMasterToken();
                shared_ptr<UserIdToken> peerUserIdToken = requestHeader->getPeerUserIdToken();
                requestBuilder->setPeerAuthTokens(peerMasterToken, peerUserIdToken);
            }
            requestBuilder->setNonReplayable(resendMsgCtx->isNonReplayable());
            return make_shared<MslControl::ErrorResult>(requestBuilder, resendMsgCtx);
        }
        case MslConstants::ResponseCode::userdataReauth:
        case MslConstants::ResponseCode::ssotokenRejected:
        {
            // If the message context cannot provide user authentication
            // data then return null.
            try {
                const MessageContext::ReauthCode reauthCode = MessageContext::ReauthCode::valueOf(errorCode);
                if (!msgCtx->getUserAuthData(reauthCode, false, true))
                    return shared_ptr<MslControl::ErrorResult>();
            } catch (const IllegalArgumentException& e) {
                throw MslInternalException("Unsupported response code mapping onto user re-authentication codes.", e);
            }

            // Otherwise we have now triggered the need for new user
            // authentication data. Fall through.
        }
        case MslConstants::ResponseCode::userReauth:
        {
            // Grab the newest master token and its read lock.
            shared_ptr<MasterToken> masterToken = getNewestMasterToken(ctx);

            // Resend the request without a user ID token.
            // Make sure the use the error header message ID + 1.
            const int64_t messageId = MessageBuilder::incrementMessageId(errorHeader->getMessageId());
            shared_ptr<MessageContext> resendMsgCtx = make_shared<ResendMessageContext>(payloads, msgCtx);
            shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, masterToken, nullptr, messageId);
            if (ctx->isPeerToPeer()) {
                shared_ptr<MasterToken> peerMasterToken = requestHeader->getPeerMasterToken();
                shared_ptr<UserIdToken> peerUserIdToken = requestHeader->getPeerUserIdToken();
                requestBuilder->setPeerAuthTokens(peerMasterToken, peerUserIdToken);
            }
            requestBuilder->setNonReplayable(resendMsgCtx->isNonReplayable());
            return make_shared<MslControl::ErrorResult>(requestBuilder, resendMsgCtx);
        }
        case MslConstants::ResponseCode::keyxRequired:
        {
            // This error will only be received by trusted network clients
            // and peer-to-peer entities that do not have a master token.
            // Make sure the use the error header message ID + 1.
            const int64_t messageId = MessageBuilder::incrementMessageId(errorHeader->getMessageId());
            shared_ptr<MessageContext> resendMsgCtx = make_shared<ResendMessageContext>(payloads, msgCtx);
            shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, nullptr, nullptr, messageId);
            if (ctx->isPeerToPeer()) {
                shared_ptr<MasterToken> peerMasterToken = requestHeader->getPeerMasterToken();
                shared_ptr<UserIdToken> peerUserIdToken = requestHeader->getPeerUserIdToken();
                requestBuilder->setPeerAuthTokens(peerMasterToken, peerUserIdToken);
            }
            // Mark the message as renewable to make sure the response can
            // be encrypted. During renewal lock acquisition we will either
            // block until we acquire the renewal lock or receive a master
            // token.
            requestBuilder->setRenewable(true);
            requestBuilder->setNonReplayable(resendMsgCtx->isNonReplayable());
            return make_shared<MslControl::ErrorResult>(requestBuilder, resendMsgCtx);
        }
        case MslConstants::ResponseCode::expired:
        {
            // Grab the newest master token and its read lock.
            shared_ptr<MasterToken> masterToken = getNewestMasterToken(ctx);
            shared_ptr<UserIdToken> userIdToken;
            if (masterToken) {
                // Grab the user ID token for the message's user. It may not be bound
                // to the newest master token if the newest master token invalidated
                // it.
                const string userId = msgCtx->getUserId();
                shared_ptr<MslStore> store = ctx->getMslStore();
                shared_ptr<UserIdToken> storedUserIdToken = (!userId.empty()) ? store->getUserIdToken(userId) : nullptr;
                userIdToken = (storedUserIdToken && storedUserIdToken->isBoundTo(masterToken)) ? storedUserIdToken : nullptr;
            } else {
                userIdToken = nullptr;
            }

            // Resend the request->
            const int64_t messageId = MessageBuilder::incrementMessageId(errorHeader->getMessageId());
            shared_ptr<MessageContext> resendMsgCtx = make_shared<ResendMessageContext>(payloads, msgCtx);
            shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, masterToken, userIdToken, messageId);
            if (ctx->isPeerToPeer()) {
                shared_ptr<MasterToken> peerMasterToken = requestHeader->getPeerMasterToken();
                shared_ptr<UserIdToken> peerUserIdToken = requestHeader->getPeerUserIdToken();
                requestBuilder->setPeerAuthTokens(peerMasterToken, peerUserIdToken);
            }
            // If the newest master token is equal to the previous
            // request's master token then mark this message as renewable.
            // During renewal lock acquisition we will either block until
            // we acquire the renewal lock or receive a master token.
            //
            // Check for a missing master token in case the remote entity
            // returned an incorrect error code.
            shared_ptr<MasterToken> requestMasterToken = requestHeader->getMasterToken();
            if (!requestMasterToken || requestMasterToken->equals(masterToken))
                requestBuilder->setRenewable(true);
            requestBuilder->setNonReplayable(resendMsgCtx->isNonReplayable());
            return make_shared<MslControl::ErrorResult>(requestBuilder, resendMsgCtx);
        }
        case MslConstants::ResponseCode::replayed:
        {
            // This error will be received if the previous request's non-
            // replayable ID is not accepted by the remote entity. In this
            // situation simply try again->
            //
            // Grab the newest master token and its read lock.
            shared_ptr<MasterToken> masterToken = getNewestMasterToken(ctx);
            shared_ptr<UserIdToken> userIdToken;
            if (masterToken) {
                // Grab the user ID token for the message's user. It may not be bound
                // to the newest master token if the newest master token invalidated
                // it.
                const string userId = msgCtx->getUserId();
                shared_ptr<MslStore> store = ctx->getMslStore();
                shared_ptr<UserIdToken> storedUserIdToken = (!userId.empty()) ? store->getUserIdToken(userId) : nullptr;
                userIdToken = (storedUserIdToken && storedUserIdToken->isBoundTo(masterToken)) ? storedUserIdToken : nullptr;
            } else {
                userIdToken = nullptr;
            }

            // Resend the request->
            const int64_t messageId = MessageBuilder::incrementMessageId(errorHeader->getMessageId());
            shared_ptr<MessageContext> resendMsgCtx = make_shared<ResendMessageContext>(payloads, msgCtx);
            shared_ptr<MessageBuilder> requestBuilder = messageFactory->createRequest(ctx, masterToken, userIdToken, messageId);
            if (ctx->isPeerToPeer()) {
                shared_ptr<MasterToken> peerMasterToken = requestHeader->getPeerMasterToken();
                shared_ptr<UserIdToken> peerUserIdToken = requestHeader->getPeerUserIdToken();
                requestBuilder->setPeerAuthTokens(peerMasterToken, peerUserIdToken);
            }

            // Mark the message as replayable or not as dictated by the
            // message context.
            requestBuilder->setNonReplayable(resendMsgCtx->isNonReplayable());
            return make_shared<MslControl::ErrorResult>(requestBuilder, resendMsgCtx);
        }
        default:
            // Nothing to do. Return null.
            return shared_ptr<MslControl::ErrorResult>();
    }
}

void MslControl::cleanupContext(shared_ptr<MslContext> ctx,
        shared_ptr<msg::MessageHeader> requestHeader,
        shared_ptr<ErrorHeader> errorHeader)
{
    // The data-reauth error codes also delete tokens in case those errors
    // are returned when a token does exist.
    switch (errorHeader->getErrorCode()) {
        case MslConstants::ResponseCode::entityReauth:
        case MslConstants::ResponseCode::entitydataReauth:
        {
            // The old master token is invalid. Delete the old
            // crypto context and any bound service tokens.
            deleteMasterToken(ctx, requestHeader->getMasterToken());
            break;
        }
        case MslConstants::ResponseCode::userReauth:
        case MslConstants::ResponseCode::userdataReauth:
        {
            // The old user ID token is invalid. Delete the old user ID
            // token and any bound service tokens. It is okay to stomp on
            // other requests when doing this because automatically
            // generated messages and replies to outstanding requests that
            // use the user ID token and service tokens will work fine.
            //
            // This will be a no-op if we received a new user ID token that
            // overwrote the old one.
            shared_ptr<MasterToken> masterToken = requestHeader->getMasterToken();
            shared_ptr<UserIdToken> userIdToken = requestHeader->getUserIdToken();
            if (masterToken && userIdToken) {
                shared_ptr<MslStore> store = ctx->getMslStore();
                store->removeUserIdToken(userIdToken);
            }
            break;
        }
        default:
            // No cleanup required.
            break;
    }
}

shared_ptr<MslControl::SendResult> MslControl::send(shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
        shared_ptr<OutputStream> out, shared_ptr<MessageBuilder> builder, bool closeDestination)
{
    shared_ptr<MasterToken> masterToken = builder->getMasterToken();
    shared_ptr<UserIdToken> userIdToken = builder->getUserIdToken();
    shared_ptr<UserIdToken> peerUserIdToken = builder->getPeerUserIdToken();

    // Ask the message context for user authentication data.
    bool userAuthDataDelayed = false;
    const string userId = msgCtx->getUserId();
    if (!userId.empty()) {
        // If we are not including a user ID token, the user authentication
        // data is required.
        const bool required = (!userIdToken);
        shared_ptr<UserAuthenticationData> userAuthData = msgCtx->getUserAuthData(MessageContext::ReauthCode::INVALID, builder->isRenewable(), required);
        if (userAuthData) {
            // We can only include user authentication data if the message
            // header will be encrypted and integrity protected.
            if (builder->willEncryptHeader() && builder->willIntegrityProtectHeader())
                builder->setUserAuthenticationData(userAuthData);

            // If the message should include user authentication data but
            // cannot at this time then we also cannot send the application
            // data as it may be user-specific. There is also no user ID token
            // otherwise the header will be encrypted.
            else
                userAuthDataDelayed = true;
        }

        // If user authentication data is required but was not provided
        // then this message may be associated with a user but not have any
        // user authentication data. For example upon user creation.
    }

    // If there is no user ID token for the remote user then check if a
    // user ID token should be created and attached.
    if ((!ctx->isPeerToPeer() && !userIdToken) ||
        (ctx->isPeerToPeer() && !peerUserIdToken))
    {
        shared_ptr<MslUser> user = msgCtx->getUser();
        if (user) {
            builder->setUser(user);

            // The user ID token may have changed and we need the latest one to
            // store the service tokens below.
            userIdToken = builder->getUserIdToken();
        }
    }

    // If we have not delayed the user authentication data, and the message
    // payloads either do not need to be encrypted or can be encrypted with
    // this message, and the message payloads either do not need to be
    // integrity protected or can be integrity protected with this message,
    // and the message is either replayable or the message will be sent non-
    // replayable and has a master token, then we can write the application
    // data now.
    const bool writeData = !userAuthDataDelayed &&
        (!msgCtx->isEncrypted() || builder->willEncryptPayloads()) &&
        (!msgCtx->isIntegrityProtected() || builder->willIntegrityProtectPayloads()) &&
        (!msgCtx->isNonReplayable() || (builder->isNonReplayable() && masterToken));
    const bool handshake = !writeData;

    // Set the message handshake flag.
    builder->setHandshake(handshake);

    // If this message is renewable...
    set<shared_ptr<KeyRequestData>> keyRequests;
    if (builder->isRenewable()) {
        // Ask for key request data if we are using entity authentication
        // data or if the master token needs renewing or if the message is
        // non-replayable.
        shared_ptr<Date> now = ctx->getRemoteTime();
        if (!masterToken || masterToken->isRenewable(now) || msgCtx->isNonReplayable()) {
            set<shared_ptr<KeyRequestData>> msgCtxKeyRequestData = msgCtx->getKeyRequestData();
            keyRequests.insert(msgCtxKeyRequestData.begin(), msgCtxKeyRequestData.end());
            for (auto keyRequest : keyRequests)
                builder->addKeyRequestData(keyRequest);
        }
    }

    // Ask the caller to perform any shared_ptr<modifications> to the
    // message and then build the message.
    shared_ptr<MessageServiceTokenBuilder> serviceTokenBuilder = make_shared<MessageServiceTokenBuilder>(ctx, msgCtx, builder);
    msgCtx->updateServiceTokens(serviceTokenBuilder, handshake);
    shared_ptr<MessageHeader> requestHeader = builder->getHeader();

    // Deliver the header that will be sent to the debug context.
    shared_ptr<MessageDebugContext> debugCtx = msgCtx->getDebugContext();
    if (debugCtx) debugCtx->sentHeader(requestHeader);

    // Update the stored crypto contexts just before sending the
    // message so we can receive new messages immediately after it is
    // sent.
    shared_ptr<KeyExchangeFactory::KeyExchangeData> keyExchangeData = builder->getKeyExchangeData();
    updateCryptoContexts(ctx, requestHeader, keyExchangeData);

    // Update the stored service tokens.
    shared_ptr<MasterToken> tokenVerificationMasterToken = (keyExchangeData) ? keyExchangeData->keyResponseData->getMasterToken() : masterToken;
    set<shared_ptr<ServiceToken>> serviceTokens = requestHeader->getServiceTokens();
    storeServiceTokens(ctx, tokenVerificationMasterToken, userIdToken, serviceTokens);

    // We will either use the header crypto context or the key exchange
    // data crypto context in trusted network mode to process the message
    // payloads.
    shared_ptr<ICryptoContext> payloadCryptoContext;
    if (!ctx->isPeerToPeer() && keyExchangeData)
        payloadCryptoContext = keyExchangeData->cryptoContext;
    else
        payloadCryptoContext = requestHeader->getCryptoContext();

    // Send the request.
    shared_ptr<OutputStream> os = (filterFactory) ? filterFactory->getOutputStream(out) : out;
    shared_ptr<MessageOutputStream> request = messageFactory->createOutputStream(ctx, os, requestHeader, payloadCryptoContext);
    request->closeDestination(closeDestination);

    // If it is okay to write the data then ask the application to write it
    // and return the real output stream. Otherwise it will be asked to do
    // so after the handshake is completed.
    if (!handshake)
        msgCtx->write(request);

    // Return the result.
    return make_shared<SendResult>(request, handshake);
}

shared_ptr<MessageInputStream> MslControl::receive(shared_ptr<MslContext> ctx,
        shared_ptr<MessageContext> msgCtx, shared_ptr<InputStream> in,
        shared_ptr<MessageHeader> request)
{
    // Grab the response.
    set<shared_ptr<KeyRequestData>> keyRequestData;
    if (request)
        keyRequestData = request->getKeyRequestData();
    map<string,shared_ptr<crypto::ICryptoContext>> cryptoContexts = msgCtx->getCryptoContexts();
    shared_ptr<InputStream> is = (filterFactory) ? filterFactory->getInputStream(in) : in;
    shared_ptr<MessageInputStream> response = messageFactory->createInputStream(ctx, is, keyRequestData, cryptoContexts);

    // Deliver the received header to the debug context.
    shared_ptr<MessageHeader> responseHeader = response->getMessageHeader();
    shared_ptr<ErrorHeader> errorHeader = response->getErrorHeader();
    shared_ptr<MessageDebugContext> debugCtx = msgCtx->getDebugContext();
    if (debugCtx) debugCtx->receivedHeader((responseHeader) ? dynamic_pointer_cast<Header>(responseHeader) :
                                                              dynamic_pointer_cast<Header>(errorHeader));

    // Pull the response master token or entity authentication data and
    // user ID token or user authentication data to attach them to any
    // thrown exceptions.
    shared_ptr<MasterToken> masterToken;
    shared_ptr<EntityAuthenticationData> entityAuthData;
    shared_ptr<UserIdToken> userIdToken;
    shared_ptr<UserAuthenticationData> userAuthData;
    if (responseHeader) {
        masterToken = responseHeader->getMasterToken();
        entityAuthData = responseHeader->getEntityAuthenticationData();
        userIdToken = responseHeader->getUserIdToken();
        userAuthData = responseHeader->getUserAuthenticationData();
    } else {
        masterToken = nullptr;
        entityAuthData = errorHeader->getEntityAuthenticationData();
        userIdToken = nullptr;
        userAuthData = nullptr;
    }

    try {
        // If there is a request make sure the response message ID equals
        // the request message ID + 1.
        if (request) {
            // Only enforce this for message headers and error headers that are
            // not entity re-authenticate or entity data re-authenticate (as in
            // those cases the remote entity is not always able to extract the
            // request message ID).
            const MslConstants::ResponseCode errorCode = (errorHeader ) ? errorHeader->getErrorCode() : MslConstants::ResponseCode::INVALID;
            if (responseHeader ||
                (errorCode != MslConstants::ResponseCode::FAIL && errorCode != MslConstants::ResponseCode::TRANSIENT_FAILURE && errorCode != MslConstants::ResponseCode::ENTITY_REAUTH && errorCode != MslConstants::ResponseCode::ENTITYDATA_REAUTH))
            {
                const int64_t responseMessageId = (responseHeader) ? responseHeader->getMessageId() : errorHeader->getMessageId();
                const int64_t expectedMessageId = MessageBuilder::incrementMessageId(request->getMessageId());
                if (responseMessageId != expectedMessageId) {
                    stringstream ss;
                    ss << "expected " << expectedMessageId << "; received " << responseMessageId;
                    throw MslMessageException(MslError::UNEXPECTED_RESPONSE_MESSAGE_ID, ss.str());
                }
            }
        }

        // Verify expected identity if specified.
        const string expectedIdentity = msgCtx->getRemoteEntityIdentity();
        if (!expectedIdentity.empty()) {
            // Reject if the remote entity identity is not equal to the
            // message entity authentication data identity.
            if (entityAuthData) {
                const string entityAuthIdentity = entityAuthData->getIdentity();
                if (!entityAuthIdentity.empty() && expectedIdentity != entityAuthIdentity) {
                    stringstream ss;
                    ss << "expected " << expectedIdentity << "; received " << entityAuthIdentity;
                    throw MslMessageException(MslError::MESSAGE_SENDER_MISMATCH, ss.str());
                }
            }

            // Reject if in peer-to-peer mode and the message sender does
            // not match.
            if (ctx->isPeerToPeer()) {
                const string sender = response->getIdentity();
                if (!sender.empty() && expectedIdentity != sender) {
                    stringstream ss;
                    ss << "expected " << expectedIdentity << "; received " << sender;
                    throw MslMessageException(MslError::MESSAGE_SENDER_MISMATCH, ss.str());
                }
            }
        }

        // Process the response.
        const string localIdentity = ctx->getEntityAuthenticationData()->getIdentity();
        if (responseHeader) {
            // If there is a request update the stored crypto contexts.
            if (request)
                updateCryptoContexts(ctx, request, response);

            // In trusted network mode the local tokens are the primary tokens.
            // In peer-to-peer mode they are the peer tokens. The master token
            // might be in the key response data.
            shared_ptr<KeyResponseData> keyResponseData = responseHeader->getKeyResponseData();
            shared_ptr<MasterToken> tokenVerificationMasterToken;
            shared_ptr<UserIdToken> localUserIdToken;
            set<shared_ptr<ServiceToken>> serviceTokens;
            if (!ctx->isPeerToPeer()) {
                tokenVerificationMasterToken = (keyResponseData) ? keyResponseData->getMasterToken() : responseHeader->getMasterToken();
                localUserIdToken = responseHeader->getUserIdToken();
                serviceTokens = responseHeader->getServiceTokens();
            } else {
                tokenVerificationMasterToken = (keyResponseData) ? keyResponseData->getMasterToken() : responseHeader->getPeerMasterToken();
                localUserIdToken = responseHeader->getPeerUserIdToken();
                serviceTokens = responseHeader->getPeerServiceTokens();
            }

            // Save any returned user ID token if the local entity is not the
            // issuer of the user ID token.
            const string userId = msgCtx->getUserId();
            if (!userId.empty() && (localUserIdToken && !localUserIdToken->isVerified()))
                ctx->getMslStore()->addUserIdToken(userId, localUserIdToken);

            // Update the stored service tokens.
            storeServiceTokens(ctx, tokenVerificationMasterToken, localUserIdToken, serviceTokens);
        }

        // Update the synchronized clock if we are a trusted network client
        // (there is a request) or peer-to-peer entity.
        shared_ptr<Date> timestamp = (responseHeader) ? responseHeader->getTimestamp() : errorHeader->getTimestamp();
        if (timestamp && (request || ctx->isPeerToPeer()))
            ctx->updateRemoteTime(timestamp);
    } catch (MslException& e) {
        e.setMasterToken(masterToken);
        e.setEntityAuthenticationData(entityAuthData);
        e.setUserIdToken(userIdToken);
        e.setUserAuthenticationData(userAuthData);
        throw e;
    }

    // Return the result.
    return response;
}

shared_ptr<MslControl::SendReceiveResult> MslControl::sendReceive(shared_ptr<MslContext> ctx,
        shared_ptr<MessageContext> msgCtx, shared_ptr<InputStream> in,
        shared_ptr<OutputStream> out, shared_ptr<MessageBuilder> builder,
        Receive recv, bool closeStreams, int64_t timeout)
{
    // Attempt to acquire the renewal lock.
    shared_ptr<BlockingQueue<MasterToken>> renewalQueue = make_shared<BlockingQueue<MasterToken>>();
    bool renewing;
    try {
        renewing = acquireRenewalLock(ctx, msgCtx, renewalQueue, builder, timeout);
//    } catch (const InterruptedException& e) {    // FIXME: Can't do this in C++
//        // Release the master token lock.
//        releaseMasterToken(ctx, builder->getMasterToken());
//
//        // This should only be if we were cancelled so return null.
//        return nullptr;
    } catch (...) {
        // Release the master token lock.
        releaseMasterToken(ctx, builder->getMasterToken());
        throw;
    }

    // Send the request and receive the response.
    shared_ptr<SendResult> sent;
    shared_ptr<MessageInputStream> response;

    // We want to make sure we clean up even if the something in the code below
    // throws, so we have to make an RAII object.
    class Cleanup
    {
    public:
        Cleanup(MslControl *mslControl, bool renewing, shared_ptr<MslContext> ctx,
                shared_ptr<BlockingQueue<MasterToken>> renewalQueue,
                shared_ptr<MessageInputStream> response, shared_ptr<MasterToken> masterToken)
        : mslControl(mslControl), renewing(renewing), ctx(ctx), renewalQueue(renewalQueue),
          response(response), masterToken(masterToken) {}
        ~Cleanup() {
            // Release the renewal lock.
            if (renewing)
                mslControl->releaseRenewalLock(ctx, renewalQueue, response);

            // Release the master token lock.
            mslControl->releaseMasterToken(ctx, masterToken);
        }
    private:
        MslControl * const mslControl;
        const bool renewing;
        shared_ptr<MslContext> ctx;
        shared_ptr<BlockingQueue<MasterToken>> renewalQueue;
        shared_ptr<MessageInputStream> response;
        shared_ptr<MasterToken> masterToken;
    };
    Cleanup cleanup(this, renewing, ctx, renewalQueue, response, builder->getMasterToken());

    // Send the request.
    builder->setRenewable(renewing);
    sent = send(ctx, msgCtx, out, builder, closeStreams);

    // Receive the response if expected, if we sent a handshake request,
    // or if we expect a response when renewing tokens and either key
    // request data was included or a master token and user
    // authentication data was included in a renewable message.
    shared_ptr<MessageHeader> requestHeader = sent->request->getMessageHeader();
    set<shared_ptr<KeyRequestData>> keyRequestData = requestHeader->getKeyRequestData();
    if (recv == Receive::ALWAYS || sent->handshake ||
        (recv == Receive::RENEWING &&
         (!keyRequestData.empty() ||
          (requestHeader->isRenewable() && requestHeader->getMasterToken() && requestHeader->getUserAuthenticationData()))))
    {
        response = receive(ctx, msgCtx, in, requestHeader);
        response->closeSource(closeStreams);

        // If we received an error response then cleanup.
        shared_ptr<ErrorHeader> errorHeader = response->getErrorHeader();
        if (errorHeader)
            cleanupContext(ctx, requestHeader, errorHeader);
    }

    // Return the response.
    return make_shared<SendReceiveResult>(response, sent);
}

bool MslControl::acquireRenewalLock(shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
        shared_ptr<BlockingQueue<MasterToken>> queue, shared_ptr<MessageBuilder> builder,
        int64_t timeout)
{
    shared_ptr<MasterToken> masterToken = builder->getMasterToken();
    shared_ptr<UserIdToken> userIdToken = builder->getUserIdToken();
    const string userId = msgCtx->getUserId();

    // If the application data needs to be encrypted and the builder will
    // not encrypt payloads, or the application data needs to be integrity
    // protected and the bulder will not integrity protect payloads, or if
    // the master token is expired, or if the message is to be sent with
    // user authentication data and the builder will not encrypt and
    // integrity protect the header, then we must either mark this message
    // as renewable to perform a handshake or get a master token from a
    // renewing thread.
    //
    // If the message has been marked renewable then we must either mark
    // this message as renewable or receive a new master token.
    //
    // If the message must be marked non-replayable and we do not have a
    // master token then we must mark this message as renewable to perform
    // a handshake or receive a new master token.
    shared_ptr<Date> startTime = ctx->getRemoteTime();
    if ((msgCtx->isEncrypted() && !builder->willEncryptPayloads()) ||
        (msgCtx->isIntegrityProtected() && !builder->willIntegrityProtectPayloads()) ||
        builder->isRenewable() ||
        (!masterToken && msgCtx->isNonReplayable()) ||
        (masterToken && masterToken->isExpired(startTime)) ||
        (!userIdToken && !userId.empty() && (!builder->willEncryptHeader() || !builder->willIntegrityProtectHeader())) ||
        (msgCtx->isRequestingTokens() && (!masterToken || (!userId.empty() && !userIdToken))))
    {
        do {
            // We do not have a master token or this message is non-
            // replayable. Try to acquire the renewal lock on this MSL
            // context so we can send a handshake message.
            shared_ptr<BlockingQueue<MasterToken>> ctxRenewingQueue = renewingContexts.putIfAbsent(ctx, queue);

            // If there is no one else already renewing then our queue has
            // acquired the renewal lock.
            if (!ctxRenewingQueue)
                return true;

            // Otherwise we need to wait for a master token from the
            // renewing request.
            shared_ptr<MasterToken> newMasterToken = ctxRenewingQueue->poll(timeout);

            // If timed out throw an exception.
            if (!newMasterToken)
                throw TimeoutException("acquireRenewalLock timed out.");

            // Put the same master token back on the renewing queue so
            // anyone else waiting can also proceed.
            ctxRenewingQueue->add(newMasterToken);

            // If the renewing request did not acquire a master token then
            // try again to acquire renewal ownership.
            if (newMasterToken == NULL_MASTER_TOKEN)
                continue;

            // If the new master token is not equal to the previous master
            // token then release the previous master token and get the
            // newest master token.
            //
            // We cannot simply use the new master token directly since we
            // have not acquired its master token lock.
            shared_ptr<MasterToken> previousMasterToken = masterToken;
            if (!masterToken || !masterToken->equals(newMasterToken)) {
                releaseMasterToken(ctx, masterToken);
                masterToken = getNewestMasterToken(ctx);

                // If there is no newest master token (it could have been
                // deleted despite just being delivered to us) then try
                // again to acquire renewal ownership.
                if (!masterToken)
                    continue;
            }

            // The renewing request may have acquired a new user ID token.
            // Attach it to this message if the message is associated with
            // a user and we do not already have a user ID token.
            //
            // Unless the previous master token was thrown out, any user ID
            // token should still be bound to this new master token. If the
            // master token serial number has changed then our user ID
            // token is no longer valid and the new one should be attached.
            if ((!userId.empty() && !userIdToken) ||
                (userIdToken && !userIdToken->isBoundTo(masterToken)))
            {
                shared_ptr<UserIdToken> storedUserIdToken = ctx->getMslStore()->getUserIdToken(userId);
                userIdToken = (storedUserIdToken && storedUserIdToken->isBoundTo(masterToken)) ? storedUserIdToken : nullptr;
            }

            // Update the message's master token and user ID token.
            builder->setAuthTokens(masterToken, userIdToken);

            // If the new master token is still expired then try again to
            // acquire renewal ownership.
            shared_ptr<Date> updateTime = ctx->getRemoteTime();
            if (masterToken->isExpired(updateTime))
                continue;

            // If this message is already marked renewable and the received
            // master token is the same as the previous master token then
            // we must still attempt to acquire the renewal lock.
            if (builder->isRenewable() && masterToken->equals(previousMasterToken))
                continue;

            // If this message is requesting tokens and is associated with
            // a user but there is no user ID token then we must still
            // attempt to acquire the renewal lock.
            if (msgCtx->isRequestingTokens() && !userIdToken)
                continue;

            // We may still want to renew, but it is not required. Fall
            // through.
            break;
        } while (true);
    }

    // If we do not have a master token or the master token should be
    // renewed, or we do not have a user ID token but the message is
    // associated with a user, or if the user ID token should be renewed,
    // then try to mark this message as renewable.
    shared_ptr<Date> finalTime = ctx->getRemoteTime();
    if ((!masterToken || masterToken->isRenewable(finalTime)) ||
        (!userIdToken && !msgCtx->getUserId().empty()) ||
        (userIdToken && userIdToken->isRenewable(finalTime)))
    {
        // Try to acquire the renewal lock on this MSL context.
        shared_ptr<BlockingQueue<MasterToken>> ctxRenewingQueue = renewingContexts.putIfAbsent(ctx, queue);

        // If there is no one else already renewing then our queue has
        // acquired the renewal lock.
        if (!ctxRenewingQueue)
            return true;

        // Otherwise proceed without acquiring the lock.
        return false;
    }

    // Otherwise we do not need to acquire the renewal lock.
    return false;
}

void MslControl::releaseRenewalLock(shared_ptr<MslContext> ctx,
        shared_ptr<BlockingQueue<tokens::MasterToken>> queue,
        shared_ptr<MessageInputStream> message)
{
    // Sanity check.
    if (renewingContexts.get(ctx) != queue)
        throw IllegalStateException("Attempt to release renewal lock that is not owned by this queue->");

    // If no message was received then deliver a null master token, release
    // the lock, and return immediately.
    if (!message) {
        queue->add(NULL_MASTER_TOKEN);
        renewingContexts.remove(ctx);
        return;
    }

    // If we received an error message then deliver a null master token,
    // release the lock, and return immediately.
    shared_ptr<MessageHeader> messageHeader = message->getMessageHeader();
    if (!messageHeader) {
        queue->add(NULL_MASTER_TOKEN);
        renewingContexts.remove(ctx);
        return;
    }

    // If we performed key exchange then the renewed master token should be
    // delivered.
    shared_ptr<KeyResponseData> keyResponseData = messageHeader->getKeyResponseData();
    if (keyResponseData) {
        queue->add(keyResponseData->getMasterToken());
    }

    // In trusted network mode deliver the header master token. This may be
    // null.
    else if (!ctx->isPeerToPeer()) {
        shared_ptr<MasterToken> masterToken = messageHeader->getMasterToken();
        if (masterToken)
            queue->add(masterToken);
        else
            queue->add(NULL_MASTER_TOKEN);
    }

    // In peer-to-peer mode deliver the peer master token. This may be
    // null.
    else {
        shared_ptr<MasterToken> masterToken = messageHeader->getPeerMasterToken();
        if (masterToken)
            queue->add(masterToken);
        else
            queue->add(NULL_MASTER_TOKEN);
    }

    // Release the lock.
    renewingContexts.remove(ctx);
}

void MslControl::sendError(shared_ptr<MslContext> ctx, shared_ptr<MessageDebugContext> debugCtx,
        shared_ptr<MessageHeader> requestHeader, int64_t messageId,
        const MslError& error, const string& userMessage, shared_ptr<OutputStream> out)
{
    // Create error header->
    shared_ptr<ErrorHeader> errorHeader = messageFactory->createErrorResponse(ctx, messageId, error, userMessage);
    if (debugCtx) debugCtx->sentHeader(errorHeader);

    // Determine encoder format.
    shared_ptr<MslEncoderFactory> encoder = ctx->getMslEncoderFactory();
    shared_ptr<MessageCapabilities> capabilities = (requestHeader)
        ? MessageCapabilities::intersection(ctx->getMessageCapabilities(), requestHeader->getMessageCapabilities())
        : ctx->getMessageCapabilities();
    set<MslEncoderFormat> formats = (capabilities) ? capabilities->getEncoderFormats() : set<MslEncoderFormat>();
    const MslEncoderFormat format = encoder->getPreferredFormat(formats);

    // Send error response->
    shared_ptr<MessageOutputStream> response = messageFactory->createOutputStream(ctx, out, errorHeader, format);
    response->close();
}

/**
 * <p>This service sends a request to the remote entity and returns the
 * response.</p>
 *
 * <p>This class will only be used by trusted network clients, peer-to-peer
 * clients, and peer-to-peer servers.</p>
 */
// FIXME: These methods should not be inline.
class MslControl::RequestService : protected Callable<shared_ptr<MslChannel>>
{
public:
    virtual ~RequestService() {}

    /**
     * Create a new message request service.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param remoteEntity remote entity URL.
     * @param expectResponse response expectation.
     * @param timeout connect, read, and renewal lock acquisition timeout
     *        in milliseconds.
     */
    RequestService(MslControl *mslControl, shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
            shared_ptr<Url> remoteEntity, Receive expectResponse, int64_t timeout)
    : Callable(mslControl, ctx, msgCtx)
    , remoteEntity(remoteEntity)
    , in(nullptr)
    , out(nullptr)
    , openedStreams(false)
    , builder(nullptr)
    , expectResponse(expectResponse)
    , timeout(timeout)
    , msgCount(0)
    {}

    /**
     * Create a new message request service.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param expectResponse response expectation.
     * @param timeout read and renewal lock acquisition timeout in
     *        milliseconds.
     */
    RequestService(MslControl *mslControl, shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
            shared_ptr<InputStream> in, shared_ptr<OutputStream> out, Receive expectResponse, int64_t timeout)
    : Callable(mslControl, ctx, msgCtx)
    , remoteEntity(nullptr)
    , in(in)
    , out(out)
    , openedStreams(false)
    , builder(nullptr)
    , expectResponse(expectResponse)
    , timeout(timeout)
    , msgCount(0)
    {}

    /**
     * Create a new message request service.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param remoteEntity remote entity URL.
     * @param builder request message builder.
     * @param expectResponse response expectation.
     * @param timeout connect, read, and renewal lock acquisition timeout
     *        in milliseconds.
     * @param msgCount number of messages that have already been sent or
     *        received.
     */
    RequestService(MslControl *mslControl, shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
            shared_ptr<Url> remoteEntity, shared_ptr<MessageBuilder> builder, Receive expectResponse,
            int64_t timeout, int32_t msgCount)
    : Callable(mslControl, ctx, msgCtx)
    , remoteEntity(remoteEntity)
    , in(nullptr)
    , out(nullptr)
    , openedStreams(false)
    , builder(builder)
    , expectResponse(expectResponse)
    , timeout(timeout)
    , msgCount(msgCount)
    {}

    /**
     * Create a new message request service.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param builder request message builder->
     * @param timeout renewal lock acquisition timeout in milliseconds.
     * @param msgCount number of messages that have already been sent or
     *        received.
     */
    RequestService(MslControl *mslControl, shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
            shared_ptr<InputStream> in, shared_ptr<OutputStream> out,
            shared_ptr<MessageBuilder> builder, int64_t timeout, int32_t msgCount)
    : Callable(mslControl, ctx, msgCtx)
    , remoteEntity(nullptr)
    , in(in)
    , out(out)
    , openedStreams(false)
    , builder(builder)
    , expectResponse(Receive::ALWAYS)
    , timeout(timeout)
    , msgCount(msgCount)
    {}

    /**
     * @return the established MSL channel or {@code null} if cancelled or
     *         interrupted.
     * @throws MslException if there was an error creating or processing
     *         a message.
     * @throws IOException if there was an error reading or writing a
     *         message.
     * @throws TimeoutException if the thread timed out while trying to
     *         acquire the renewal lock.
     * @see java.util.concurrent.Callable#call()
     */
    virtual shared_ptr<MslChannel> operator()() override
    {
        // If we do not already have a connection then establish one.
        int64_t lockTimeout;
        if (!in || !out) {
            try {
                // Set up the connection.
                remoteEntity->setTimeout(timeout);

                // Connect. Keep track of how much time this takes to subtract
                // that from the lock timeout timeout->
                const int64_t start = Date::now()->getTime();
                shared_ptr<Connection> conn = remoteEntity->openConnection();
                out = conn->getOutputStream();
                in = conn->getInputStream();
                lockTimeout = timeout - (Date::now()->getTime() - start);
                openedStreams = true;
            } catch (const IOException& e) {
                // If a message builder was provided then release the
                // master token read lock.
                if (builder)
                    mslControl->releaseMasterToken(ctx, builder->getMasterToken());

                // Close any open streams.
                // We don't care about an I/O exception on close.
                if (out) try { out->close(); } catch (const IOException& ioe) { }
                if (in) try { in->close(); } catch (const IOException& ioe) { }

                // If we were cancelled then return null.
//                if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?
                throw e;
            } catch (...) {
                // If a message builder was provided then release the
                // master token read lock.
                if (builder)
                    mslControl->releaseMasterToken(ctx, builder->getMasterToken());

                // Close any open streams.
                // We don't care about an I/O exception on close.
                if (out) try { out->close(); } catch (const IOException& ioe) { }
                if (in) try { in->close(); } catch (const IOException& ioe) { }

                throw;
            }
        } else {
            lockTimeout = timeout;
        }

        // If no builder was provided then build a new request. This will
        // acquire the master token lock.
        if (!builder) {
            // FIXME: How to handle cancellation?
//            try {
                builder = mslControl->buildRequest(ctx, msgCtx);
//            } catch (const InterruptedException& e) {
//                // Close the streams if we opened them.
//                // We don't care about an I/O exception on close.
//                if (openedStreams) {
//                    try { out->close(); } catch (const IOException& ioe) { }
//                    try { in->close(); } catch (const IOException& ioe) { }
//                }
//
//                // We were cancelled so return null.
//                return nullptr;
//            }
        }

        try {
            // Execute. This will release the master token lock.
            shared_ptr<MslChannel> channel = execute(msgCtx, builder, lockTimeout, msgCount);

            // If the channel was established clear the cached payloads.
            if (channel && channel->output())
                channel->output()->stopCaching();

            // Close the input stream if we opened it and there is no
            // response. This may be necessary to transmit data
            // buffered in the output stream, and the caller will not
            // be given a message input stream by which to close it.
            //
            // We don't care about an I/O exception on close.
            if (openedStreams && (!channel || !channel->input()))
                try { in->close(); } catch (const IOException& ioe) { }

            // Return the established channel.
            return channel;
          // FIXME: How to handle cancellation?
//        } catch (const InterruptedException& e) {
//            // Close the streams if we opened them.
//            // We don't care about an I/O exception on close.
//            if (openedStreams) {
//                try { out->close(); } catch (const IOException& ioe) { }
//                try { in->close(); } catch (const IOException& ioe) { }
//            }
//
//            // We were cancelled so return null.
//            return nullptr;
        } catch (...) {
            // Close the streams if we opened them.
            // We don't care about an I/O exception on close.
            if (openedStreams) {
                try { out->close(); } catch (const IOException& ioe) { }
                try { in->close(); } catch (const IOException& ioe) { }
            }

            // If we were cancelled then return null.
//            if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?
            throw;
        }
    }

private:

    /**
     * <p>Send the provided request and receive a response from the remote
     * entity. Any necessary handshake messages will be sent.</p>
     *
     * <p>If an error was received and cannot be handled the returned MSL
     * channel will have {@code null} for its message output stream.</p>
     *
     * @param msgCtx message context.
     * @param builder request message builder->
     * @param timeout renewal lock acquisition timeout in milliseconds.
     * @param msgCount number of messages sent or received so far.
     * @return the established MSL channel or {@code null} if cancelled or
     *         if the maximum message count is hit.
     * @throws MslException if there was an error creating or processing
     *         a message.
     * @throws IOException if there was an error reading or writing a
     *         message.
     * @throws InterruptedException if the thread is interrupted while
     *         trying to acquire a master token's read lock.
     * @throws TimeoutException if the thread timed out while trying to
     *         acquire the renewal lock.
     */
    shared_ptr<MslChannel> execute(shared_ptr<MessageContext> msgCtx, shared_ptr<MessageBuilder> builder,
            int64_t timeout, int32_t msgCount)
    {
        // Do not do anything if cannot send and receive two more messages.
        //
        // Make sure to release the master token lock.
        if (msgCount + 2 > MslConstants::MAX_MESSAGES) {
            mslControl->releaseMasterToken(ctx, builder->getMasterToken());
            maxMessagesHit = true;
            return nullptr;
        }

        // Send the request and receive the response. This adds two to our
        // message count.
        //
        // This will release the master token lock.
        shared_ptr<SendReceiveResult> result = mslControl->sendReceive(ctx, msgCtx, in, out, builder, expectResponse, openedStreams, timeout);
        shared_ptr<MessageOutputStream> request = result->request;
        shared_ptr<MessageInputStream> response = result->response;
        msgCount += 2;

        // If we did not receive a response then we're done. Return the
        // new message output stream.
        if (!response)
            return make_shared<MslChannel>(response, request);

        // If the response is an error see if we can handle the error and
        // retry.
        shared_ptr<MessageHeader> responseHeader = response->getMessageHeader();
        if (!responseHeader) {
            // Close the request and response. The response is an error and
            // the request is not usable.
            try {
                request->close();
            } catch (const IOException& e) {
                // If we were cancelled then return null.
//                if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?
                // Otherwise we don't care about an I/O exception on close.
            }
            try {
                response->close();
            } catch (const IOException& e) {
                // If we were cancelled then return null.
//                if (cancelled(e)) return nullptr;if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?
                // Otherwise we don't care about an I/O exception on close.
            }

            // Build the error response. This will acquire the master token
            // lock.
            shared_ptr<ErrorHeader> errorHeader = response->getErrorHeader();
            shared_ptr<ErrorResult> errMsg = mslControl->buildErrorResponse(ctx, msgCtx, result, errorHeader);

            // If there is no error response then return the error.
            if (!errMsg)
                return make_shared<MslChannel>(response, nullptr);

            // In trusted network mode send the response in a new request.
            // In peer-to-peer mode reuse the connection.
            shared_ptr<MslChannel> newChannel;
            shared_ptr<MessageBuilder> requestBuilder = errMsg->builder;
            shared_ptr<MessageContext> resendMsgCtx = errMsg->msgCtx;
            if (!ctx->isPeerToPeer()) {
                // The master token lock acquired from buildErrorResponse()
                // will be released when the service executes.
                RequestService service(mslControl, ctx, resendMsgCtx, remoteEntity, requestBuilder, expectResponse, timeout, msgCount);
                newChannel = service();
                maxMessagesHit = service.maxMessagesHit;
            } else {
                // Send the error response. Recursively execute this
                // because it may take multiple messages to succeed with
                // sending the request.
                //
                // The master token lock will be released by the recursive
                // call to execute().
                newChannel = execute(resendMsgCtx, requestBuilder, timeout, msgCount);
            }

            // If the maximum message count was hit or if there is no new
            // response then return the original error response.
            if (maxMessagesHit || (newChannel && !(newChannel->input())))
                return make_shared<MslChannel>(response, nullptr);

            // Return the new channel, which may contain an error or be
            // null if cancelled or interrupted.
            return newChannel;
        }

        // If we are in trusted network mode...
        if (!ctx->isPeerToPeer()) {
            // If we did not perform a handshake then we're done. Deliver
            // the response.
            if (!result->handshake)
                return make_shared<MslChannel>(response, request);

            // We did perform a handshake. Re-send the message over a new
            // connection to allow the application to send its data.
            //
            // Close the request and response. The response will be
            // discarded and we will be issuing a new request->
            try {
                request->close();
            } catch (const IOException& e) {
                // If we were cancelled then return null.
//                if (cancelled(e)) return nullptr;if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?
                // Otherwise we don't care about an I/O exception on close.
            }
            try {
                response->close();
            } catch (const IOException& e) {
                // If we were cancelled then return null.
//                if (cancelled(e)) return nullptr;if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?
                // Otherwise we don't care about an I/O exception on close.
            }

            // The master token lock acquired from buildResponse() will be
            // released when the service executes.
            shared_ptr<MessageContext> resendMsgCtx = make_shared<ResendMessageContext>(vector<shared_ptr<PayloadChunk>>(), msgCtx);
            shared_ptr<MessageBuilder> requestBuilder = mslControl->buildResponse(ctx, msgCtx, responseHeader);
            RequestService service(mslControl, ctx, resendMsgCtx, remoteEntity, requestBuilder, expectResponse, timeout, msgCount);
            return service();
        }

        // We are in peer-to-peer mode...
        //
        // If we did perform a handshake. Re-send the message over the same
        // connection to allow the application to send its data. This may
        // also return key response data.
        if (result->handshake) {
            // Close the request and response. The response will be
            // discarded and we will be issuing a new request->
            try {
                request->close();
            } catch (const IOException& e) {
                // If we were cancelled then return null.
//                if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?
                // Otherwise we don't care about an I/O exception on close.
            }
            try {
                response->close();
            } catch (const IOException& e) {
                // If we were cancelled then return null.
//                if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?
                // Otherwise we don't care about an I/O exception on close.
            }

            // Now resend.
            //
            // The master token lock acquired from buildResponse() will be
            // released by the recursive call to execute().
            shared_ptr<MessageContext> resendMsgCtx = make_shared<ResendMessageContext>(vector<shared_ptr<PayloadChunk>>(), msgCtx);
            shared_ptr<MessageBuilder> requestBuilder = mslControl->buildResponse(ctx, msgCtx, responseHeader);
            return execute(resendMsgCtx, requestBuilder, timeout, msgCount);
        }

        // Otherwise we did send our application data (which may have been
        // zero-length) so we do not need to re-send our message.
        //
        // If the response contains key request data, or is renewable and
        // contains a master token and user authentication data, then we
        // need to return a response to perform key exchange and/or provide
        // a user ID token.
        set<shared_ptr<KeyRequestData>> responseKeyxData = responseHeader->getKeyRequestData();
        if (!responseKeyxData.empty() ||
            (responseHeader->isRenewable() && (responseHeader->getMasterToken() && responseHeader->getUserAuthenticationData())))
        {
            // Build the response. This will acquire the master token lock.
            shared_ptr<MessageContext> keyxMsgCtx = make_shared<KeyxResponseMessageContext>(msgCtx);
            shared_ptr<MessageBuilder> keyxBuilder = mslControl->buildResponse(ctx, keyxMsgCtx, responseHeader);

            // We should release the master token lock when finished, but
            // there is one case where we should not.
            struct Cleanup
            {
                Cleanup(MslControl * mslControl, shared_ptr<MslContext> ctx, shared_ptr<MasterToken> masterToken)
                : mslControl(mslControl), ctx(ctx), masterToken(masterToken) {}
                ~Cleanup() { if (releaseLock) mslControl->releaseMasterToken(ctx, masterToken); }
                MslControl * const mslControl;
                shared_ptr<MslContext> ctx;
                shared_ptr<MasterToken> masterToken;
                bool releaseLock = true;
            } cleanup(mslControl, ctx, keyxBuilder->getMasterToken());

            // If the response is not a handshake message then we do not
            // expect a reply.
            if (!response->isHandshake()) {
                // Close the request as we are issuing a new request->
                try {
                    request->close();
                } catch (const IOException& e) {
                    // If we were cancelled then return null.
//                    if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?
                    // Otherwise we don't care about an I/O exception on close.
                }

                // The remote entity is expecting a response. We need
                // to send it even if this exceeds the maximum number of
                // messages. We're guaranteed to stop sending more
                // messages after this response.
                //
                // Return the original message input stream and the new
                // message output stream to the caller.
                keyxBuilder->setRenewable(false);
                shared_ptr<SendResult> newResult = mslControl->send(ctx, keyxMsgCtx, out, keyxBuilder, openedStreams);
                return make_shared<MslChannel>(response, newResult->request);
            }

            // Otherwise the remote entity may still have to send us the
            // application data in a reply.
            else {
                // Close the request and response. The response will be
                // discarded and we will be issuing a new request->
                try {
                    request->close();
                } catch (const IOException& e) {
                    // If we were cancelled then return null.
//                    if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?
                    // Otherwise we don't care about an I/O exception on close.
                }
                try {
                    response->close();
                } catch (const IOException& e) {
                    // If we were cancelled then return null.
//                    if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?
                    // Otherwise we don't care about an I/O exception on close.
                }

                cleanup.releaseLock = false;
                return execute(keyxMsgCtx, keyxBuilder, timeout, msgCount);
            }
        }

        // Return the established MSL channel to the caller.
        return make_shared<MslChannel>(response, request);
    }

private:
    /**
     * A delayed input stream does not open the real input stream until
     * one of its methods is called.
     */
    /** MSL context. */
    //shared_ptr<MslContext> ctx;
    /** Message context. */
    //shared_ptr<MessageContext> msgCtx;
    /** Remote entity URL. */
    shared_ptr<Url> remoteEntity;
    /** Remote entity input stream. */
    shared_ptr<InputStream> in;
    /** Remote entity output stream. */
    shared_ptr<OutputStream> out;
    /** True if we opened the streams. */
    bool openedStreams;
    /** Request message builder-> */
    shared_ptr<MessageBuilder> builder;
    /** Response expectation. */
    Receive expectResponse;
    /** Connect and read timeout in milliseconds. */
    int64_t timeout;
    /** Number of messages sent or received so far. */
    int32_t msgCount;

    /** True if the maximum message count is hit. */
    bool maxMessagesHit = false;

};  // class MslControl::RequestService

/**
 * <p>This service receives a request from a remote entity, and either
 * returns the received message or automatically generates a reply (and
 * returns null).</p>
 *
 * <p>This class will only be used by trusted-network servers and peer-to-
 * peer servers.</p>
 */
// FIXME: These methods should not be inline.
class MslControl::ReceiveService : protected Callable<shared_ptr<MessageInputStream>>
{
public:
    virtual ~ReceiveService() {}

    /**
     * Create a new message receive service.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param timeout renewal lock aquisition timeout in milliseconds.
     */
    ReceiveService(MslControl *mslControl, shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
            shared_ptr<InputStream> in, shared_ptr<OutputStream> out, int64_t timeout)
    : Callable(mslControl, ctx, msgCtx)
    , in(in)
    , out(out)
    , timeout(timeout)
    {}

    /**
     * @return the received message or {@code null} if cancelled.
     * @throws MslException if there was an error with the received message
     *         or an error creating an automatically generated response.
     * @throws MslErrorResponseException if there was an error sending an
     *         automatically generated error response.
     * @throws IOException if there was an error reading or writing a
     *         message.
     * @throws TimeoutException if the thread timed out while trying to
     *         acquire the renewal lock.
     * @see java.util.concurrent.Callable#call()
     */
    virtual shared_ptr<MessageInputStream> operator()() override
    {
        shared_ptr<MessageDebugContext> debugCtx = msgCtx->getDebugContext();

        // Read the incoming message.
        shared_ptr<MessageInputStream> request;
        try {
            request = mslControl->receive(ctx, msgCtx, in, nullptr);
//        } catch (const InterruptedException& e) {  // FIXME: How to handle cancellation?
//            // We were cancelled so return null.
//            return nullptr;
        } catch (const MslException& e) {
            // If we were cancelled then return null.
//            if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?

            // Try to send an error response.
            try {
                shared_ptr<MasterToken> masterToken = e.getMasterToken();
                shared_ptr<EntityAuthenticationData> entityAuthData = e.getEntityAuthenticationData();
                const MslError error = e.getError();
                const string userMessage = mslControl->messageRegistry->getUserMessage(error, vector<string>());
                mslControl->sendError(ctx, debugCtx, nullptr, e.getMessageId(), error, userMessage, out);
            } catch (const IException& rt) {
//                // If we were cancelled then return null.
//                if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                throw MslErrorResponseException("Error receiving the message header->", rt, e);
            }
            throw e;
        } catch (const IOException& e) {
            // If we were cancelled then return null.
//            if (cancelled(t)) return nullptr;  // FIXME: How to handle cancellation?

            // Maybe we can send an error message.
            try {
                mslControl->sendError(ctx, debugCtx, nullptr, -1, MslError::MSL_COMMS_FAILURE, string(), out);
            } catch (const IException& rt) {
                // If we were cancelled then return null.
//                if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                throw MslErrorResponseException("Error receiving the message header->", rt, e);
            }
            throw e;
        } catch (const IException& t) {
            // If we were cancelled then return null.
//            if (cancelled(t)) return nullptr;  // FIXME: How to handle cancellation?

            // Try to send an error response.
            try {
                mslControl->sendError(ctx, debugCtx, nullptr, -1, MslError::INTERNAL_EXCEPTION, string(), out);
            } catch (const IException& rt) {
                // If we were cancelled then return null.
//                if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                throw MslErrorResponseException("Error receiving the message header->", rt, t);
            }
            throw MslInternalException("Error receiving the message header->", t);
        }

        // Return error headers to the caller.
        shared_ptr<MessageHeader> requestHeader = request->getMessageHeader();
        if (!requestHeader)
            return request;

        // If the message is not a handshake message deliver it to the
        // caller.
        try {
            if (!request->isHandshake())
                return request;
        } catch (const IException& t) {
            // If we were cancelled then return null.
//            if (cancelled(t)) return nullptr;  // FIXME: How to handle cancellation?

            // Try to send an error response.
            try {
                int64_t requestMessageId = requestHeader->getMessageId();
                mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError::INTERNAL_EXCEPTION, string(), out);
            } catch (const IException& rt) {
                // If we were cancelled then return null.
//                if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?


                throw MslErrorResponseException("Error peeking into the message payloads.", rt, t);
            }
            throw MslInternalException("Error peeking into the message payloads.", t);
        }

        // This is a handshake request so automatically return a response.
        shared_ptr<MessageBuilder> responseBuilder;
        {  // scope for Cleanup, like java 'finally'
            struct Cleanup {
                Cleanup(shared_ptr<MessageInputStream> request) : request(request) {}
                ~Cleanup() { try { request->close(); } catch (const IOException& e) {} }
                shared_ptr<MessageInputStream> request;
            } cleanup(request);
            try {
                // In peer-to-peer mode this will acquire the local entity's
                // master token read lock.
                responseBuilder = mslControl->buildResponse(ctx, msgCtx, request->getMessageHeader());
    //        } catch (const InterruptedException& e) {  // FIXME: How to handle cancellation?
    //            // We were cancelled so return null.
    //            return nullptr;
            } catch (const MslException& e) {
                // If we were cancelled then return null.
    //            if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?

                // Try to send an error response.
                try {
                    const MslError error = e.getError();
                    shared_ptr<MessageCapabilities> caps = requestHeader->getMessageCapabilities();
                    vector<string> languages = (caps) ? caps->getLanguages() : vector<string>();
                    const string userMessage = mslControl->messageRegistry->getUserMessage(error, languages);
                    mslControl->sendError(ctx, debugCtx, requestHeader, e.getMessageId(), error, userMessage, out);
                } catch (const IException& rt) {
                    // If we were cancelled then return null.
    //                if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?


                    throw MslErrorResponseException("Error creating an automatic handshake response.", rt, e);
                }
                throw e;
            } catch (const IException&  t) {
                // If we were cancelled then return null.
    //            if (cancelled(t)) return nullptr;  // FIXME: How to handle cancellation?

                // Try to send an error response.
                try {
                    int64_t requestMessageId = requestHeader->getMessageId();
                    mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError::INTERNAL_EXCEPTION, string(), out);
                } catch (const IException& rt) {
                    // If we were cancelled then return null.
    //                if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?


                    throw MslErrorResponseException("Error creating an automatic handshake response.", rt, t);
                }
                throw MslInternalException("Error creating an automatic handshake response.", t);
            }
        }
        // If we are in trusted services mode then no additional data is
        // expected. Send the handshake response and return null. The next
        // message from the remote entity can be retrieved by another call
        // to receive.
        shared_ptr<MessageContext> keyxMsgCtx = make_shared<KeyxResponseMessageContext>(msgCtx);
        if (!ctx->isPeerToPeer()) {
            try {
                responseBuilder->setRenewable(false);
                mslControl->send(ctx, keyxMsgCtx, out, responseBuilder, false);
                return nullptr;
//            } catch (const InterruptedException& e) {  // FIXME: How to handle cancellation?
//                // We were cancelled so return null.
//                return nullptr;
            } catch (const MslException& e) {
                // If we were cancelled then return null.
//                if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?

                // Try to send an error response.
                try {
                    int64_t requestMessageId = requestHeader->getMessageId();
                    const MslError error = e.getError();
                    shared_ptr<MessageCapabilities> caps = requestHeader->getMessageCapabilities();
                    vector<string> languages = (caps) ? caps->getLanguages() : vector<string>();
                    const string userMessage = mslControl->messageRegistry->getUserMessage(error, languages);
                    mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, error, userMessage, out);
                } catch (const IException& rt) {
                    // If we were cancelled then return null.
//                        if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                    throw MslErrorResponseException("Error sending an automatic handshake response.", rt, e);
                }
                throw e;
            } catch (const IOException& e) {
                // If we were cancelled then return null.
//                if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?

                // Maybe we can send an error response.
                try {
                    int64_t requestMessageId = requestHeader->getMessageId();
                    mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError::MSL_COMMS_FAILURE, string(), out);
                } catch (const IException& rt) {
                    // If we were cancelled then return null.
//                        if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                    throw MslErrorResponseException("Error sending an automatic handshake response.", rt, e);
                }
                throw e;
            } catch (const IException& t) {
                // If we were cancelled then return null.
//                if (cancelled(t)) return nullptr;  // FIXME: How to handle cancellation?


                // Try to send an error response.
                try {
                    int64_t requestMessageId = requestHeader->getMessageId();
                    mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError::INTERNAL_EXCEPTION, string(), out);
                } catch (const IException& rt) {
                    // If we were cancelled then return null.
//                    if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                    throw MslErrorResponseException("Error sending an automatic handshake response.", rt, t);
                }
                throw MslInternalException("Error sending an automatic handshake response.", t);
            }
        }

        // Since we are in peer-to-peer mode our response may contain key
        // request data. Therefore we may receive another request after the
        // remote entity's key exchange completes containing peer
        // authentication tokens for the local entity.
        //
        // The master token lock acquired from buildResponse() will be
        // released when the service executes.
        //
        // We have received one message.
        RequestService service(mslControl, ctx, keyxMsgCtx, in, out, responseBuilder, timeout, 1);
        shared_ptr<MslChannel> channel = service();

        // The MSL channel message output stream can be discarded since it
        // only contained a handshake response.
        if (channel)
            return channel->input();
        return nullptr;
    }

private:
    /** Remote entity input stream. */
    shared_ptr<InputStream> in;
    /** Remote entity output stream. */
    shared_ptr<OutputStream> out;
    /** Read timeout in milliseconds. */
    const int64_t timeout;

};  // class MslControl::ReceiveService

/**
 * <p>This service sends a response to the remote entity.</p>
 *
 * <p>This class will only be used trusted network servers and peer-to-peer
 * servers.</p>
 */
// FIXME: These methods should not be inline.
class MslControl::RespondService : protected Callable<shared_ptr<MslChannel>>
{
protected:
    /** Request message input stream. */
    shared_ptr<MessageInputStream> request;
    /** Remote entity input stream. */
    shared_ptr<InputStream> in;
    /** Remote entity output stream. */
    shared_ptr<OutputStream> out;
    /** Read timeout in milliseconds. */
    int64_t timeout;

public:
    virtual ~RespondService() {}

    /**
     * Create a new message respond service.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param request request message input stream.
     * @param timeout renewal lock acquisition timeout in milliseconds.
     */
    RespondService(MslControl *mslControl, shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
            shared_ptr<InputStream> in, shared_ptr<OutputStream> out, shared_ptr<MessageInputStream> request,
            int64_t timeout)
    : Callable(mslControl, ctx, msgCtx)
    , request(request)
    , in(in)
    , out(out)
    , timeout(timeout)
    {
        if (request->getErrorHeader())
            throw MslInternalException("Respond service created for an error message.");
    }

protected:
    /**
     * Send the response as a trusted network server.
     *
     * @param builder response message builder->
     * @param msgCount number of messages that have already been sent or
     *        received.
     * @return the MSL channel if the response was sent or null if
     *         cancelled, interrupted, if the response could not be sent
     *         encrypted or integrity protected when required, a user could
     *         not be attached due to lack of a master token, or if the
     *         maximum message count is hit.
     * @throws MslException if there was an error creating the response.
     * @throws MslErrorResponseException if there was an error sending an
     *         automatically generated error response.
     * @throws IOException if there was an error writing the message.
     * @throws InterruptedException if the thread is interrupted while
     *         trying to delete an old master token the sent message is
     *         replacing.
     */
    shared_ptr<MslChannel> trustedNetworkExecute(shared_ptr<MessageBuilder> builder, int32_t msgCount)
    {
        { // scope for Cleanup

            // Release the master token read lock with any exit from this scope.
            // FIXME: duplicate in RequestService::execute
            struct Cleanup
            {
                Cleanup(MslControl * mslControl, shared_ptr<MslContext> ctx, shared_ptr<MasterToken> masterToken)
                : mslControl(mslControl), ctx(ctx), masterToken(masterToken) {}
                ~Cleanup() { mslControl->releaseMasterToken(ctx, masterToken); }
                MslControl * const mslControl;
                shared_ptr<MslContext> ctx;
                shared_ptr<MasterToken> masterToken;
            } cleanup(mslControl, ctx, builder->getMasterToken());

            shared_ptr<MessageDebugContext> debugCtx = msgCtx->getDebugContext();
            shared_ptr<MessageHeader> requestHeader = request->getMessageHeader();

            // Do nothing if we cannot send one more message.
            if (msgCount + 1 > MslConstants::MAX_MESSAGES)
                return nullptr;

            // If the response must be encrypted or integrity protected but
            // cannot then send an error requesting it. The client must re-
            // initiate the transaction.
            MslError securityRequired = MslError::OK;
            if (msgCtx->isIntegrityProtected() && !builder->willIntegrityProtectPayloads())
                securityRequired = MslError::RESPONSE_REQUIRES_INTEGRITY_PROTECTION;
            else if (msgCtx->isEncrypted() && !builder->willEncryptPayloads())
                securityRequired = MslError::RESPONSE_REQUIRES_ENCRYPTION;
            else
                securityRequired = MslError::OK;
            if (securityRequired != MslError::OK) {
                // Try to send an error response.
                try {
                    const int64_t requestMessageId = MessageBuilder::decrementMessageId(builder->getMessageId());
                    mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, securityRequired, string(), out);
                    return nullptr;
                } catch (const IException& rt) {
                    // If we were cancelled then return null.
//                    if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                    throw MslErrorResponseException(string("Response requires encryption or integrity protection but cannot be protected: ") + securityRequired.getMessage(), rt);
                }
            }

            // If the response wishes to attach a user ID token but there is no
            // master token then send an error requesting the master token. The
            // client must re-initiate the transaction.
            if (msgCtx->getUser() && !builder->getMasterToken() && !builder->getKeyExchangeData()) {
                // Try to send an error response.
                try {
                    const int64_t requestMessageId = MessageBuilder::decrementMessageId(builder->getMessageId());
                    mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError::RESPONSE_REQUIRES_MASTERTOKEN, string(), out);
                    return nullptr;
                } catch (const IException& rt) {
                    // If we were cancelled then return null.
//                    if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                    throw MslErrorResponseException("Response wishes to attach a user ID token but there is no master token.", rt);
                }
            }

            // Otherwise simply send the response.
            builder->setRenewable(false);
            shared_ptr<SendResult> result = mslControl->send(ctx, msgCtx, out, builder, false);
            return make_shared<MslChannel>(request, result->request);
        }
    }

    /**
     * Send the response as a peer-to-peer entity.
     *
     * @param msgCtx message context.
     * @param builder response message builder->
     * @param msgCount number of messages sent or received so far.
     * @return a MSL channel if the response was sent or null if cancelled,
     *         interrupted, or if the response could not be sent encrypted
     *         or integrity protected when required, a user could not be
     *         attached due to lack of a master token, or if the maximum
     *         message count is hit.
     * @throws MslException if there was an error creating or processing a
     *         message.
     * @throws MslErrorResponseException if there was an error sending an
     *         automatically generated error response.
     * @throws IOException if there was an error writing the message.
     * @throws InterruptedException if the thread is interrupted while
     *         trying to acquire the master token lock.
     * @throws TimeoutException if the thread timed out while trying to
     *         acquire the renewal lock.
     */
    shared_ptr<MslChannel> peerToPeerExecute(shared_ptr<MessageContext> msgCtx,
            shared_ptr<MessageBuilder> builder, int32_t msgCount)
    {
        shared_ptr<MessageDebugContext> debugCtx = msgCtx->getDebugContext();
        shared_ptr<MessageHeader> requestHeader = request->getMessageHeader();

        // Do nothing if we cannot send and receive two more messages.
        //
        // Make sure to release the master token lock.
        if (msgCount + 2 > MslConstants::MAX_MESSAGES) {
            mslControl->releaseMasterToken(ctx, builder->getMasterToken());
            return nullptr;
        }

        // If the response wishes to attach a user ID token but there is no
        // master token then send an error requesting the master token. The
        // client must re-initiate the transaction.
        if (msgCtx->getUser() != nullptr && builder->getPeerMasterToken() == nullptr && builder->getKeyExchangeData() == nullptr) {
            // Release the master token lock and try to send an error
            // response.
            mslControl->releaseMasterToken(ctx, builder->getMasterToken());
            try {
                const int64_t requestMessageId = MessageBuilder::decrementMessageId(builder->getMessageId());
                mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError::RESPONSE_REQUIRES_MASTERTOKEN, string(), out);
                return nullptr;
            } catch (const IException& rt) {
                // If we were cancelled then return null.
//                if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                throw MslErrorResponseException("Response wishes to attach a user ID token but there is no master token.", rt);
            }
        }

        // Send the response. A reply is not expected, but may be received.
        // This adds two to our message count.
        //
        // This will release the master token lock.
        shared_ptr<SendReceiveResult> result = mslControl->sendReceive(ctx, msgCtx, in, out, builder, Receive::RENEWING, false, timeout);
        shared_ptr<MessageInputStream> response = result->response;
        msgCount += 2;

        // If we did not receive a response then we're done. Return the
        // original message input stream and the new message output stream.
        if (response == nullptr)
            return make_shared<MslChannel>(request, result->request);

        // If the response is an error see if we can handle the error and
        // retry.
        shared_ptr<MessageHeader> responseHeader = response->getMessageHeader();
        if (responseHeader == nullptr) {
            // Close the response. We have everything we need.
            try {
                response->close();
            } catch (const IException& t) {
                // If we were cancelled then return null.
//                if (cancelled(t)) return nullptr;  // FIXME: How to handle cancellation?
                // Otherwise we don't care about an exception on close.
            }

            // Build the error response. This will acquire the master token
            // lock.
            shared_ptr<ErrorHeader> errorHeader = response->getErrorHeader();
            shared_ptr<ErrorResult> errMsg = mslControl->buildErrorResponse(ctx, msgCtx, result, errorHeader);

            // If there is no error response then return the error.
            if (errMsg == nullptr)
                return nullptr;

            // Send the error response. Recursively execute this because it
            // may take multiple messages to succeed with sending the
            // response.
            //
            // The master token lock will be released by the recursive call
            // to peerToPeerExecute().
            shared_ptr<MessageBuilder> requestBuilder = errMsg->builder;
            shared_ptr<MessageContext> resendMsgCtx = errMsg->msgCtx;
            return peerToPeerExecute(resendMsgCtx, requestBuilder, msgCount);
        }

        // If we performed a handshake then re-send the message over the
        // same connection so this time the application can send its data.
        if (result->handshake) {
            // Close the response as we are discarding it.
            try {
                response->close();
            } catch (const IException& t) {
                // If we were cancelled then return null.
//                if (cancelled(t)) return nullptr;  // FIXME: How to handle cancellation?
                // Otherwise we don't care about an exception on close.
            }

            // This will acquire the local entity's master token read lock.
            // The master token lock will be released by the recursive call
            // to peerToPeerExecute().
            shared_ptr<MessageContext> resendMsgCtx = make_shared<ResendMessageContext>(vector<shared_ptr<PayloadChunk>>(), msgCtx);
            shared_ptr<MessageBuilder> requestBuilder = mslControl->buildResponse(ctx, resendMsgCtx, responseHeader);
            return peerToPeerExecute(resendMsgCtx, requestBuilder, msgCount);
        }

        // Otherwise we did send our application data (which may have been
        // zero-length) so we do not need to re-send our message. Return
        // the new message input stream and the new message output stream.
        return make_shared<MslChannel>(result->response, result->request);
    }

public:

    /**
     * @return a {@link MslChannel} on success or {@code null} if cancelled,
     *         interrupted, if an error response was received (peer-to-peer
     *         mode only), if the response could not be sent encrypted or
     *         integrity protected when required (trusted network-mode
     *         only), or if the maximum number of messages is hit.
     * @throws MslException if there was an error creating the response.
     * @throws MslErrorResponseException if there was an error sending an
     *         automatically generated error response.
     * @throws IOException if there was an error writing the message.
     * @see java.util.concurrent.Callable#call()
     */
    virtual shared_ptr<MslChannel> operator()() override
    {
        shared_ptr<MessageDebugContext> debugCtx = msgCtx->getDebugContext();

        shared_ptr<MessageHeader> requestHeader = request->getMessageHeader();
        shared_ptr<MessageBuilder> builder;
        try {
            // In peer-to-peer mode this will acquire the local entity's
            // master token read lock.
            builder = mslControl->buildResponse(ctx, msgCtx, requestHeader);
//        } catch (const InterruptedException& e) {  // FIXME: How to handle cancellation?
//            // We were cancelled so return null.
//            return nullptr;
        } catch (const MslException& e) {
            // If we were cancelled then return null.
//            if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?

            try {
                const MslError error = e.getError();
                shared_ptr<MessageCapabilities> caps = requestHeader->getMessageCapabilities();
                const vector<std::string> languages = (caps != nullptr) ? caps->getLanguages() : vector<std::string>();
                const string userMessage = mslControl->messageRegistry->getUserMessage(error, languages);
                mslControl->sendError(ctx, debugCtx, requestHeader, e.getMessageId(), error, userMessage, out);
            } catch (const IException& rt) {
                throw MslErrorResponseException("Error building the response.", rt, e);
            }
            throw e;
        } catch (const IException& t) {
            // If we were cancelled then return null.
//            if (cancelled(t)) return nullptr;  // FIXME: How to handle cancellation?

            try {
                mslControl->sendError(ctx, debugCtx, requestHeader, -1, MslError::INTERNAL_EXCEPTION, string(), out);
            } catch (const IException& rt) {
                throw MslErrorResponseException("Error building the response.", rt, t);
            }
            throw MslInternalException("Error building the response.", t);
        }

        // At most three messages would have been involved in the original
        // receive.
        try {
            // Send the response. This will release the master token lock.
            shared_ptr<MslChannel> channel;
            if (!ctx->isPeerToPeer())
                channel = trustedNetworkExecute(builder, 3);
            else
                channel = peerToPeerExecute(msgCtx, builder, 3);

            // Clear any cached payloads.
            if (channel != nullptr)
                channel->output()->stopCaching();

            // Return the established channel.
            return channel;
//        } catch (const InterruptedException& e) {  // FIXME: How to handle cancellation?
//            // We were cancelled so return null.
//            return nullptr;
        } catch (const IOException& e) {
            // If we were cancelled then return null.
//            if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?

            // Maybe we can send an error response.
            try {
                const int64_t requestMessageId = MessageBuilder::decrementMessageId(builder->getMessageId());
                mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError::MSL_COMMS_FAILURE, string(), out);
            } catch (const IException& rt) {
                // If we were cancelled then return null.
//                if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                throw MslErrorResponseException("Error sending the response.", rt, e);
            }
            throw e;
        } catch (const MslException& e) {
            // If we were cancelled then return null.
//            if (cancelled(e)) return nullptr;  // FIXME: How to handle cancellation?

            // Maybe we can send an error response.
            try {
                const int64_t requestMessageId = MessageBuilder::decrementMessageId(builder->getMessageId());
                const MslError error = e.getError();
                shared_ptr<MessageCapabilities> caps = requestHeader->getMessageCapabilities();
                const vector<string> languages = (caps != nullptr) ? caps->getLanguages() : vector<string>();
                const string userMessage = mslControl->messageRegistry->getUserMessage(error, languages);
                mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, error, userMessage, out);
            } catch (const IException& rt) {
                // If we were cancelled then return null.
//                if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                throw MslErrorResponseException("Error sending the response.", rt, e);
            }
            throw e;
        } catch (const IException& t) {
            // If we were cancelled then return null.
//            if (cancelled(t)) return nullptr;  // FIXME: How to handle cancellation?

            // Maybe we can send an error response.
            try {
                const int64_t requestMessageId = MessageBuilder::decrementMessageId(builder->getMessageId());
                mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError::INTERNAL_EXCEPTION, string(), out);
            } catch (const IException& rt) {
                // If we were cancelled then return null.
//                if (cancelled(rt)) return nullptr;  // FIXME: How to handle cancellation?

                throw MslErrorResponseException("Error sending the response.", rt, t);
            }
            throw MslInternalException("Error sending the response.", t);
        }
    }

}; // class MslControl::RespondService

/**
 * <p>This service sends an error response to the remote entity.</p>
 *
 * <p>This class will only be used trusted network servers and peer-to-peer
 * entities.</p>
 */
class MslControl::ErrorService : protected Callable<bool>
{
private:
    MslControl * const mslControl;
    /** Application error. */
    const ApplicationError appError;
    /** Request message input stream. */
    shared_ptr<MessageInputStream> request;
    /** Remote entity output stream. */
    shared_ptr<OutputStream> out;

public:
    virtual ~ErrorService() {}

    /**
     * Create a new error service.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param err the application error.
     * @param out remote entity output stream.
     * @param request request message input stream.
     */
    ErrorService(MslControl * mslControl, shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
            const ApplicationError& appError, shared_ptr<OutputStream> out,
            shared_ptr<MessageInputStream> request)
    : Callable(mslControl, ctx, msgCtx)
    , mslControl(mslControl)
    , appError(appError)
    , request(request)
    , out(out)
    {
        if (request->getErrorHeader())
            throw MslInternalException("Error service created for an error message.");
    }

    /**
     * @return true on success or false if cancelled or interrupted.
     * @throws MslException if there was an error creating the response.
     * @throws IOException if there was an error writing the message.
     * @see java.util.concurrent.Callable#call()
     */
    bool operator()() override
    {
        shared_ptr<MessageDebugContext> debugCtx = msgCtx->getDebugContext();
        shared_ptr<MessageHeader> header = request->getMessageHeader();

        try {
            // Identify the correct MSL error.
            MslError error = MslError::OK;
            switch (appError) {
                case ENTITY_REJECTED:
                    error = (header->getMasterToken())
                        ? MslError::MASTERTOKEN_REJECTED_BY_APP
                        : MslError::ENTITY_REJECTED_BY_APP;
                    break;
                case USER_REJECTED:
                    error = (header->getUserIdToken())
                        ? MslError::USERIDTOKEN_REJECTED_BY_APP
                        : MslError::USER_REJECTED_BY_APP;
                    break;
                default:
                {
                    stringstream ss;
                    ss << "Unhandled application error " << appError << ".";
                    throw MslInternalException(ss.str());
                }
            }

            // Build and send the error response.
            shared_ptr<MessageCapabilities> caps = header->getMessageCapabilities();
            const vector<string> languages = (caps) ? caps->getLanguages() : vector<string>();
            const string userMessage = mslControl->messageRegistry->getUserMessage(error, languages);
            mslControl->sendError(ctx, debugCtx, header, header->getMessageId(), error, userMessage, out);

            // Success.
            return true;
        } catch (const MslException& e) {
            // If we were cancelled then return false.
//            if (cancelled(e)) return false;  // FIXME: How to handle cancellation?

            // We failed to return an error response. Deliver the exception
            // to the application.
            throw e;
        } catch (const IException& t) {
            // If we were cancelled then return false.
//            if (cancelled(t)) return false;  // FIXME: How to handle cancellation?

            // An unexpected exception occurred.
            throw MslInternalException("Error building the error response.", t);
        }
    }

}; // class MslControl::ErrorService

/**
 * <p>This service sends a message to a remote entity.</p>
 *
 * <p>This class is only used from trusted network clients and peer-to-peer
 * entities.</p>
 */
class MslControl::SendService : protected Callable<shared_ptr<MessageOutputStream>>
{
private:
    /** The request service. */
    shared_ptr<RequestService> requestService;

public:
    virtual ~SendService() {}

    /**
     * Create a new message send service.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param remoteEntity remote entity URL.
     * @param timeout connect, read, and renewal lock acquisition timeout
     *        in milliseconds.
     */
    SendService(MslControl * mslControl, shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
            shared_ptr<Url> remoteEntity, int64_t timeout)
        : Callable(mslControl, ctx, msgCtx)
        , requestService(make_shared<RequestService>(mslControl, ctx, msgCtx, remoteEntity, Receive::NEVER, timeout))
    {
    }

    /**
     * Create a new message send service.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param timeout read and renewal lock acquisition timeout in
     *        milliseconds.
     */
    SendService(MslControl * mslControl, shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
            shared_ptr<InputStream> in, shared_ptr<OutputStream> out, int64_t timeout)
        : Callable(mslControl, ctx, msgCtx)
        , requestService(make_shared<RequestService>(mslControl, ctx, msgCtx, in, out, Receive::NEVER, timeout))
    {
    }

    /**
     * @return the established MSL channel or {@code null} if cancelled or
     *         interrupted.
     * @throws MslException if there was an error creating or processing
     *         a message.
     * @throws IOException if there was an error reading or writing a
     *         message.
     * @throws TimeoutException if the thread timed out while trying to
     *         acquire the renewal lock.
     * @see java.util.concurrent.Callable#call()
     */
    virtual shared_ptr<MessageOutputStream> operator()() override
    {
        shared_ptr<MslChannel> channel = (*requestService)();
        return (channel) ? channel->output() : shared_ptr<MessageOutputStream>();
    }
}; // class MslControl::SendService

/**
 * <p>This service sends a message to the remote entity using a request as
 * the basis for the response.</p>
 *
 * <p>This class will only be used trusted network servers.</p>
 */
class MslControl::PushService : public MslControl::RespondService
{
public:
    virtual ~PushService() {}

    /**
     * Create a new message push service.
     *
     * @param ctx MSL context.
     * @param msgCtx message context.
     * @param in remote entity input stream.
     * @param out remote entity output stream.
     * @param request request message input stream.
     * @param timeout renewal lock acquisition timeout in milliseconds.
     */
    PushService(MslControl * mslControl, shared_ptr<MslContext> ctx, shared_ptr<MessageContext> msgCtx,
            shared_ptr<InputStream> in, shared_ptr<OutputStream> out, shared_ptr<MessageInputStream> request, int64_t timeout)
        : RespondService(mslControl, ctx, msgCtx, in, out, request, timeout)
    {}

    /**
     * @return a {@link MslChannel} on success or {@code null} if cancelled,
     *         interrupted, if the response could not be sent encrypted or
     *         integrity protected when required, or if the maximum number
     *         of messages is hit.
     * @throws MslException if there was an error creating the response.
     * @throws MslErrorResponseException if there was an error sending an
     *         automatically generated error response.
     * @throws IOException if there was an error writing the message.
     * @see java.util.concurrent.Callable#call()
     */
    virtual shared_ptr<MslChannel> operator()() override
    {
        shared_ptr<MessageDebugContext> debugCtx = msgCtx->getDebugContext();

        shared_ptr<MessageHeader> requestHeader = request->getMessageHeader();
        shared_ptr<MessageBuilder> builder;
        try {
            builder = mslControl->buildDetachedResponse(ctx, msgCtx, requestHeader);
        } catch (const MslException& e) {
            // If we were cancelled then return null.
//            if (cancelled(e)) return shared_ptr<MslChannel>();  // FIXME: How to handle cancellation?

            try {
                const MslError error = e.getError();
                shared_ptr<MessageCapabilities> caps = requestHeader->getMessageCapabilities();
                vector<string> languages = (caps) ? caps->getLanguages() : vector<string>();
                const string userMessage = mslControl->messageRegistry->getUserMessage(error, languages);
                mslControl->sendError(ctx, debugCtx, requestHeader, e.getMessageId(), error, userMessage, out);
            } catch (const IException& rt) {
                throw MslErrorResponseException("Error building the message.", rt, e);
            }
            throw e;
        } catch (const IException& t) {
            // If we were cancelled then return null.
//            if (cancelled(t)) return null;  // FIXME: How to handle cancellation?

            try {
                mslControl->sendError(ctx, debugCtx, requestHeader, -1, MslError::INTERNAL_EXCEPTION, string(), out);
            } catch (const IException& rt) {
                throw MslErrorResponseException("Error building the message.", rt, t);
            }
            throw MslInternalException("Error building the message.", t);
        }

        try {
            // Send the message. This will release the master token lock.
            shared_ptr<MslChannel> channel = trustedNetworkExecute(builder, 0);

            // Clear any cached payloads.
            if (channel)
                channel->output()->stopCaching();

            // Return the established channel.
            return channel;
//        } catch (final InterruptedException e) {  // FIXME: How to handle cancellation?
//            // We were cancelled so return null.
//            return nullptr;
        } catch (const IOException& e) {
            // If we were cancelled then return null.
//            if (cancelled(e)) return null;  // FIXME: How to handle cancellation?

            // Maybe we can send an error response.
            try {
                const int64_t requestMessageId = MessageBuilder::decrementMessageId(builder->getMessageId());
                mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError::MSL_COMMS_FAILURE, string(), out);
            } catch (const IException& rt) {
                // If we were cancelled then return null.
//                if (cancelled(rt)) return null;  // FIXME: How to handle cancellation?

                throw MslErrorResponseException("Error pushing the message.", rt, e);
            }
            throw e;
        } catch (const MslException& e) {
            // If we were cancelled then return null.
//            if (cancelled(e)) return null;  // FIXME: How to handle cancellation?

            // Maybe we can send an error response.
            try {
                const int64_t requestMessageId = MessageBuilder::decrementMessageId(builder->getMessageId());
                const MslError error = e.getError();
                shared_ptr<MessageCapabilities> caps = requestHeader->getMessageCapabilities();
                vector<string> languages = (caps) ? caps->getLanguages() : vector<string>();
                const string userMessage = mslControl->messageRegistry->getUserMessage(error, languages);
                mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, error, userMessage, out);
            } catch (const IException& rt) {
                // If we were cancelled then return null.
//                if (cancelled(rt)) return null;  // FIXME: How to handle cancellation?

                throw MslErrorResponseException("Error pushing the message.", rt, e);
            }
            throw e;
        } catch (const IException& t) {
            // If we were cancelled then return null.
//            if (cancelled(t)) return null;  // FIXME: How to handle cancellation?

            // Maybe we can send an error response.
            try {
                const int64_t requestMessageId = MessageBuilder::decrementMessageId(builder->getMessageId());
                mslControl->sendError(ctx, debugCtx, requestHeader, requestMessageId, MslError::INTERNAL_EXCEPTION, string(), out);
            } catch (const IException& rt) {
                // If we were cancelled then return null.
//                if (cancelled(rt)) return null;  // FIXME: How to handle cancellation?

                throw MslErrorResponseException("Error pushing the message.", rt, t);
            }
            throw MslInternalException("Error pushing the message.", t);
        }
    }
}; // class MslControl::PushService

future<shared_ptr<MessageOutputStream>> MslControl::send(shared_ptr<MslContext> ctx,
                                                         shared_ptr<MessageContext> msgCtx,
                                                         shared_ptr<Url> remoteEntity,
                                                         int64_t timeout)
{
    shared_ptr<MessageContext> sendMsgCtx = make_shared<SendMessageContext>(msgCtx);
    SendService service(this, ctx, sendMsgCtx, remoteEntity, timeout);
    return executor->submit(service);
}

future<shared_ptr<MessageOutputStream>> MslControl::send(shared_ptr<MslContext> ctx,
                                                         shared_ptr<MessageContext> msgCtx,
                                                         shared_ptr<InputStream> in,
                                                         shared_ptr<OutputStream> out,
                                                         int64_t timeout)
{
    shared_ptr<MessageContext> sendMsgCtx = make_shared<SendMessageContext>(msgCtx);
    SendService service(this, ctx, sendMsgCtx, in, out, timeout);
    return executor->submit(service);
}

future<shared_ptr<MslChannel>> MslControl::push(shared_ptr<MslContext> ctx,
                                                shared_ptr<MessageContext> msgCtx,
                                                shared_ptr<InputStream> in,
                                                shared_ptr<OutputStream> out,
                                                shared_ptr<MessageInputStream> request,
                                                int64_t timeout)
{
    if (ctx->isPeerToPeer())
        throw IllegalStateException("This method cannot be used in peer-to-peer mode.");
    if (request->getErrorHeader())
        throw IllegalArgumentException("Request message input stream cannot be for an error message.");
    PushService service(this, ctx, msgCtx, in, out, request, timeout);
    return executor->submit(service);
}

future<shared_ptr<MessageInputStream>> MslControl::receive(shared_ptr<MslContext> ctx,
                                                           shared_ptr<MessageContext> msgCtx,
                                                           shared_ptr<InputStream> in,
                                                           shared_ptr<OutputStream> out,
                                                           int64_t timeout)
{
    ReceiveService service(this, ctx, msgCtx, in, out, timeout);
    return executor->submit(service);
}

future<shared_ptr<MslChannel>> MslControl::respond(shared_ptr<MslContext> ctx,
                                                   shared_ptr<MessageContext> msgCtx,
                                                   shared_ptr<InputStream> in,
                                                   shared_ptr<OutputStream> out,
                                                   shared_ptr<MessageInputStream> request,
                                                   int64_t timeout)
{
    if (request->getErrorHeader())
        throw IllegalArgumentException("Request message input stream cannot be for an error message.");
    RespondService service(this, ctx, msgCtx, in, out, request, timeout);
    return executor->submit(service);
}

future<bool> MslControl::error(shared_ptr<MslContext> ctx,
                               shared_ptr<MessageContext> msgCtx,
                               ApplicationError err,
                               shared_ptr<OutputStream> out,
                               shared_ptr<MessageInputStream> request)
{
    if (request->getErrorHeader())
        throw IllegalArgumentException("Request message input stream cannot be for an error message.");
    ErrorService service(this, ctx, msgCtx, err, out, request);
    return executor->submit(service);
}
                
future<shared_ptr<MslChannel>> MslControl::request(shared_ptr<MslContext> ctx,
                                                   shared_ptr<MessageContext> msgCtx,
                                                   shared_ptr<Url> remoteEntity,
                                                   int64_t timeout)
{
    if (ctx->isPeerToPeer())
        throw IllegalStateException("This method cannot be used in peer-to-peer mode.");
    RequestService service(this, ctx, msgCtx, remoteEntity, Receive::ALWAYS, timeout);
    return executor->submit(service);
}
                
future<shared_ptr<MslChannel>> MslControl::request(shared_ptr<MslContext> ctx,
                                                   shared_ptr<MessageContext> msgCtx,
                                                   shared_ptr<InputStream> in,
                                                   shared_ptr<OutputStream> out,
                                                   int64_t timeout)
{
    if (!ctx->isPeerToPeer())
        throw IllegalStateException("This method cannot be used in trusted network mode.");
    RequestService service(this, ctx, msgCtx, in, out, Receive::ALWAYS, timeout);
    return executor->submit(service);
}

}}} // namespace netflix::msl::msg

