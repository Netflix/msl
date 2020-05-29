/**
 * Copyright (c) 2016-2020 Netflix, Inc.  All rights reserved.
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

#include <gtest/gtest.h>
#include <MslConstants.h>
#include <MslCryptoException.h>
#include <MslEncodingException.h>
#include <MslError.h>
#include <MslException.h>
#include <MslInternalException.h>
#include <MslMasterTokenException.h>
#include <crypto/ICryptoContext.h>
#include <crypto/NullCryptoContext.h>
#include <crypto/SessionCryptoContext.h>
#include <crypto/SymmetricCryptoContext.h>
#include <entityauth/EntityAuthenticationScheme.h>
#include <tokens/MasterToken.h>
#include <tokens/ServiceToken.h>
#include <tokens/UserIdToken.h>
#include <util/MslStore.h>
#include <util/SimpleMslStore.h>
#include <memory>
#include <set>
#include <string>

#include "../userauth/MockEmailPasswordAuthenticationFactory.h"
#include "../util/MockMslContext.h"
#include "../util/MslTestUtils.h"

using namespace std;
using namespace testing;
using namespace netflix::msl::crypto;
using namespace netflix::msl::entityauth;
using namespace netflix::msl::tokens;
using namespace netflix::msl::userauth;

namespace netflix {
namespace msl {
namespace util {

namespace {
const string KEYSET_ID = "keyset";
const string USER_ID = "userid";

/** Maximum number of randomly generated tokens. */
//const int MAX_TOKENS = 3;

/** Stress test pool shutdown timeout in milliseconds. */
//const int STRESS_TIMEOUT_MILLIS = 3000;

shared_ptr<string> NULL_NAME;
shared_ptr<MasterToken> NULL_MASTER_TOKEN;
shared_ptr<UserIdToken> NULL_USER_ID_TOKEN;
} // namespace anonymous

/**
 * Simple MSL store unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
class SimpleMslStoreTest : public ::testing::Test
{
public:
	SimpleMslStoreTest()
		: ctx(make_shared<MockMslContext>(EntityAuthenticationScheme::NONE, false))
		, store(make_shared<SimpleMslStore>())
	{}

protected:
	/** MSL context. */
	shared_ptr<MslContext> ctx;

	/** MSL store. */
	shared_ptr<MslStore> store;
	SecretKey NULL_KEY;
};

TEST_F(SimpleMslStoreTest, storeCryptoContext)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	EXPECT_FALSE(store->getCryptoContext(masterToken));

	shared_ptr<ICryptoContext> cc1 = make_shared<SymmetricCryptoContext>(ctx, KEYSET_ID, masterToken->getEncryptionKey(), masterToken->getSignatureKey(), NULL_KEY);
	store->setCryptoContext(masterToken, cc1);
	shared_ptr<ICryptoContext> cc2 = store->getCryptoContext(masterToken);
	EXPECT_TRUE(cc2);
	EXPECT_EQ(cc1.get(), cc2.get());
	EXPECT_EQ(*masterToken, *store->getMasterToken());
}

TEST_F(SimpleMslStoreTest, replaceCryptoContext)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<ICryptoContext> cc1 = make_shared<SymmetricCryptoContext>(ctx, KEYSET_ID, masterToken->getEncryptionKey(), masterToken->getSignatureKey(), NULL_KEY);
	shared_ptr<ICryptoContext> cc2 = make_shared<NullCryptoContext>();

	store->setCryptoContext(masterToken, cc1);
	shared_ptr<ICryptoContext> cc3 = store->getCryptoContext(masterToken);
	EXPECT_EQ(cc1.get(), cc3.get());
	EXPECT_NE(cc2.get(), cc3.get());

	store->setCryptoContext(masterToken, cc2);
	shared_ptr<ICryptoContext> cc4 = store->getCryptoContext(masterToken);
	EXPECT_NE(cc1.get(), cc4.get());
	EXPECT_EQ(cc2.get(), cc4.get());
	EXPECT_EQ(*masterToken, *store->getMasterToken());
}

TEST_F(SimpleMslStoreTest, removeCryptoContext)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();

	store->setCryptoContext(masterToken, cryptoContext);
	store->removeCryptoContext(masterToken);
	EXPECT_FALSE(store->getMasterToken());
	EXPECT_FALSE(store->getCryptoContext(masterToken));
}

TEST_F(SimpleMslStoreTest, clearCryptoContext)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<ICryptoContext> cc1 = make_shared<SymmetricCryptoContext>(ctx, KEYSET_ID, masterToken->getEncryptionKey(), masterToken->getSignatureKey(), NULL_KEY);
	store->setCryptoContext(masterToken, cc1);
	store->clearCryptoContexts();
	EXPECT_FALSE(store->getCryptoContext(masterToken));
	EXPECT_FALSE(store->getMasterToken());
}

TEST_F(SimpleMslStoreTest, twoCryptoContexts)
{
	shared_ptr<MasterToken> mtA = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<MasterToken> mtB = MslTestUtils::getMasterToken(ctx, 2, 1);

	shared_ptr<ICryptoContext> ccMtA1 = make_shared<SessionCryptoContext>(ctx, mtA);
	shared_ptr<ICryptoContext> ccMtB1 = make_shared<SessionCryptoContext>(ctx, mtB);
	store->setCryptoContext(mtA, ccMtA1);
	store->setCryptoContext(mtB, ccMtB1);

	shared_ptr<ICryptoContext> ccMtA2 = store->getCryptoContext(mtA);
	EXPECT_TRUE(ccMtA2);
	EXPECT_EQ(ccMtA1.get(), ccMtA2.get());

	shared_ptr<ICryptoContext> ccMtB2 = store->getCryptoContext(mtB);
	EXPECT_TRUE(ccMtB2);
	EXPECT_EQ(ccMtB1.get(), ccMtB2.get());

	EXPECT_EQ(*mtB, *store->getMasterToken());
}

TEST_F(SimpleMslStoreTest, replaceTwoCryptoContexts)
{
	shared_ptr<MasterToken> mtA = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<MasterToken> mtB = MslTestUtils::getMasterToken(ctx, 2, 1);

	shared_ptr<ICryptoContext> ccMtA1 = make_shared<SessionCryptoContext>(ctx, mtA);
	shared_ptr<ICryptoContext> ccMtB1 = make_shared<SessionCryptoContext>(ctx, mtB);
	store->setCryptoContext(mtA, ccMtA1);
	store->setCryptoContext(mtB, ccMtB1);
	EXPECT_EQ(*mtB, *store->getMasterToken());

	shared_ptr<ICryptoContext> ccNull = make_shared<NullCryptoContext>();
	store->setCryptoContext(mtA, ccNull);

	shared_ptr<ICryptoContext> ccMtA2 = store->getCryptoContext(mtA);
	EXPECT_TRUE(ccMtA2);
	EXPECT_NE(ccMtA1.get(), ccMtA2.get());
	EXPECT_EQ(ccNull.get(), ccMtA2.get());

	shared_ptr<ICryptoContext> ccMtB2 = store->getCryptoContext(mtB);
	EXPECT_TRUE(ccMtB2);
	EXPECT_EQ(ccMtB1.get(), ccMtB2.get());

	EXPECT_EQ(*mtB, *store->getMasterToken());
}

TEST_F(SimpleMslStoreTest, clearTwoCryptoContexts)
{
	shared_ptr<MasterToken> mtA = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<MasterToken> mtB = MslTestUtils::getMasterToken(ctx, 2, 1);

	shared_ptr<ICryptoContext> ccMtA1 = make_shared<SessionCryptoContext>(ctx, mtA);
	shared_ptr<ICryptoContext> ccMtB1 = make_shared<SessionCryptoContext>(ctx, mtB);
	store->setCryptoContext(mtA, ccMtA1);
	store->setCryptoContext(mtB, ccMtB1);

	store->clearCryptoContexts();
	EXPECT_FALSE(store->getCryptoContext(mtA));
	EXPECT_FALSE(store->getCryptoContext(mtB));
	EXPECT_FALSE(store->getMasterToken());
}

TEST_F(SimpleMslStoreTest, removeTwoCryptoContexts)
{
	shared_ptr<MasterToken> mtA = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<MasterToken> mtB = MslTestUtils::getMasterToken(ctx, 2, 1);

	shared_ptr<ICryptoContext> ccMtA1 = make_shared<SessionCryptoContext>(ctx, mtA);
	shared_ptr<ICryptoContext> ccMtB1 = make_shared<SessionCryptoContext>(ctx, mtB);
	store->setCryptoContext(mtA, ccMtA1);
	store->setCryptoContext(mtB, ccMtB1);

	store->removeCryptoContext(mtA);
	EXPECT_FALSE(store->getCryptoContext(mtA));
	EXPECT_EQ(ccMtB1.get(), store->getCryptoContext(mtB).get());
}

/**
 * Crypto context add/remove stress test runner.
 *
 * Randomly adds or removes a crypto context for one of many master tokens
 * (by master token entity identity). Also iterates through the set crypto
 * contexts.
 */
//private static class CryptoContextStressor implements Runnable {
//	/**
//	 * Create a new crypto context stressor.
//	 *
//	 * @param ctx MSL context.
//	 * @param store MSL store->
//	 * @param count the number of master token identities to stress.
//	 */
//	public CryptoContextStressor(final MslContext ctx, final MslStore store, final int count) {
//		this.ctx = ctx;
//		this.store = store;
//		this.count = count;
//	}
//
//	/* (non-Javadoc)
//	 * @see java.lang.Runnable#run()
//	 */
//	@Override
//	public void run() {
//		final Random r = new Random();
//
//		try {
//			for (int i = 0; i < 10 * count; ++i) {
//				final int tokenIndex = r.nextInt(count);
//				shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, tokenIndex, 1);
//				final int option = r.nextInt(4);
//				switch (option) {
//				case 0:
//					store->setCryptoContext(masterToken, null);
//					break;
//				case 1:
//					shared_ptr<ICryptoContext> cryptoContext = new SessionCryptoContext(ctx, masterToken);
//					store->setCryptoContext(masterToken, cryptoContext);
//					break;
//				case 2:
//					store->getCryptoContext(masterToken);
//					break;
//				case 3:
//					store->removeCryptoContext(masterToken);
//					break;
//				}
//			}
//		} catch (final MslMasterTokenException e) {
//			throw MslInternalException("Unexpected master token exception.", e);
//		} catch (final MslEncodingException e) {
//			throw MslInternalException("Unexpected master token encoding exception.", e);
//		} catch (final MslCryptoException e) {
//			throw MslInternalException("Unexpected master token creation exception.", e);
//		}
//	}
//
//	/** MSL context. */
//	private final MslContext ctx;
//	/** MSL store-> */
//	private final MslStore store;
//	/** Number of crypto context identities. */
//	private final int count;
//}
/*
TEST_F(SimpleMslStoreTest, stressCryptoContexts)
{
	final ExecutorService service = Executors.newCachedThreadPool();
	for (int i = 0; i < 10 * MAX_TOKENS; ++i) {
		service.execute(new CryptoContextStressor(ctx, store, MAX_TOKENS));
	}
	service.shutdown();
	assertTrue(service.awaitTermination(STRESS_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
}
*/
TEST_F(SimpleMslStoreTest, nonReplayableId)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);

	for (int i = 1; i < 10; ++i)
		EXPECT_EQ(i, store->getNonReplayableId(masterToken));
}

/*
TEST_F(SimpleMslStoreTest, wrappedNonReplayableId)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);

	for (int64_t i = 1; i < MslConstants::MAX_LONG_VALUE; ++i)
		store->getNonReplayableId(masterToken);
	EXPECT_EQ(MslConstants::MAX_LONG_VALUE, store->getNonReplayableId(masterToken));
	EXPECT_EQ(0, store->getNonReplayableId(masterToken));
	EXPECT_EQ(1, store->getNonReplayableId(masterToken));
}
*/

TEST_F(SimpleMslStoreTest, twoNonReplayableIds)
{
	shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx, 1, 2);

	for (int i = 1; i < 10; ++i) {
		EXPECT_EQ(i, store->getNonReplayableId(masterTokenA));
		EXPECT_EQ(i, store->getNonReplayableId(masterTokenB));
	}
}

TEST_F(SimpleMslStoreTest, addUserIdToken)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(USER_ID, userIdToken);

	EXPECT_EQ(*userIdToken, *store->getUserIdToken(USER_ID));
	EXPECT_FALSE(store->getUserIdToken(USER_ID + "x"));
}

TEST_F(SimpleMslStoreTest, removeUserIdToken)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(USER_ID, userIdToken);

	store->removeUserIdToken(userIdToken);
	EXPECT_FALSE(store->getUserIdToken(USER_ID));
}

TEST_F(SimpleMslStoreTest, replaceUserIdToken)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory::USER());

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(USER_ID, userIdTokenA);
	store->addUserIdToken(USER_ID, userIdTokenB);
	EXPECT_EQ(*userIdTokenB, *store->getUserIdToken(USER_ID));
}

TEST_F(SimpleMslStoreTest, twoUserIdTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory::USER());

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);

	EXPECT_EQ(*userIdTokenA, *store->getUserIdToken(userIdA));
	EXPECT_EQ(*userIdTokenB, *store->getUserIdToken(userIdB));
}

TEST_F(SimpleMslStoreTest, replaceTwoUserIdTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory::USER());

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);

	shared_ptr<UserIdToken> userIdTokenC = MslTestUtils::getUserIdToken(ctx, masterToken, 3, MockEmailPasswordAuthenticationFactory::USER());
	store->addUserIdToken(userIdA, userIdTokenC);
	EXPECT_EQ(*userIdTokenC, *store->getUserIdToken(userIdA));
	EXPECT_EQ(*userIdTokenB, *store->getUserIdToken(userIdB));
}

TEST_F(SimpleMslStoreTest, removeTwoUserIdTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory::USER());

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);

	store->removeUserIdToken(userIdTokenA);
	EXPECT_FALSE(store->getUserIdToken(userIdA));
	EXPECT_EQ(*userIdTokenB, *store->getUserIdToken(userIdB));
}

TEST_F(SimpleMslStoreTest, clearUserIdTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory::USER());

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);

	store->clearUserIdTokens();
	EXPECT_FALSE(store->getUserIdToken(userIdA));
	EXPECT_FALSE(store->getUserIdToken(userIdB));
}

TEST_F(SimpleMslStoreTest, unknownMasterTokenUserIdToken)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());

	try {
		store->addUserIdToken(USER_ID, userIdToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslException& e) {
		EXPECT_EQ(MslError::USERIDTOKEN_MASTERTOKEN_NOT_FOUND, e.getError());
	}
}

TEST_F(SimpleMslStoreTest, removeMasterTokenSameSerialNumberUserIdTokens)
{
	shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx, 2, 1);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	const string userIdC = USER_ID + "C";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterTokenA, 2, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenC = MslTestUtils::getUserIdToken(ctx, masterTokenB, 1, MockEmailPasswordAuthenticationFactory::USER());

	store->setCryptoContext(masterTokenA, cryptoContext);
	store->setCryptoContext(masterTokenB, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);
	store->addUserIdToken(userIdC, userIdTokenC);

	// We still have a master token with serial number 1 so no user ID
	// tokens should be deleted.
	store->removeCryptoContext(masterTokenA);
	EXPECT_EQ(*userIdTokenA, *store->getUserIdToken(userIdA));
	EXPECT_EQ(*userIdTokenB, *store->getUserIdToken(userIdB));
	EXPECT_EQ(*userIdTokenC, *store->getUserIdToken(userIdC));
}

TEST_F(SimpleMslStoreTest, removeMasterTokenReissuedUserIdTokens)
{
	// Master token B has a new serial number, to invalidate the old master
	// token and its user ID tokens.
	shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx, 1, 2);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	const string userIdC = USER_ID + "C";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterTokenA, 2, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenC = MslTestUtils::getUserIdToken(ctx, masterTokenB, 1, MockEmailPasswordAuthenticationFactory::USER());

	store->setCryptoContext(masterTokenA, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);
	store->setCryptoContext(masterTokenB, cryptoContext);
	store->addUserIdToken(userIdC, userIdTokenC);

	// All of master token A's user ID tokens should be deleted.
	store->removeCryptoContext(masterTokenA);
	EXPECT_FALSE(store->getUserIdToken(userIdA));
	EXPECT_FALSE(store->getUserIdToken(userIdB));
	EXPECT_EQ(*userIdTokenC, *store->getUserIdToken(userIdC));
}

TEST_F(SimpleMslStoreTest, clearCryptoContextsUserIdTokens)
{
	// Master token B has a new serial number, to invalidate the old master
	// token and its user ID tokens.
	shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx, 1, 2);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory::USER());

	store->setCryptoContext(masterTokenA, cryptoContext);
	store->setCryptoContext(masterTokenB, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);

	// All user ID tokens should be deleted.
	store->clearCryptoContexts();
	EXPECT_FALSE(store->getUserIdToken(userIdA));
	EXPECT_FALSE(store->getUserIdToken(userIdB));
}

/**
 * User ID token add/remove stress test runner.
 *
 * Randomly adds or removes user ID tokens. Also iterates through the user
 * ID tokens.
 */
//private static class UserIdTokenStressor implements Runnable {
//	/**
//	 * Create a new service token stressor.
//	 *
//	 * @param ctx MSL context.
//	 * @param store MSL store->
//	 * @param count the number of master token and user ID tokens to create
//	 *        combinations of.
//	 */
//	public UserIdTokenStressor(final MslContext ctx, final MslStore store, final int count) {
//		this.ctx = ctx;
//		this.store = store;
//		this.count = count;
//	}
//
//	/* (non-Javadoc)
//	 * @see java.lang.Runnable#run()
//	 */
//	@Override
//	public void run() {
//		final Random r = new Random();
//
//		try {
//			for (int i = 0; i < 10 * count; ++i) {
//				final int tokenIndex = r.nextInt(count);
//				shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, tokenIndex, 1);
//				final long userId = r.nextInt(count);
//				shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, userId, MockEmailPasswordAuthenticationFactory::USER());
//
//				final int option = r.nextInt(3);
//				switch (option) {
//				case 0:
//				{
//					store->setCryptoContext(masterToken, new NullCryptoContext());
//					store->addUserIdToken(USER_ID + userId, userIdToken);
//					break;
//				}
//				case 1:
//				{
//					store->getUserIdToken(USER_ID + userId);
//					break;
//				}
//				case 2:
//				{
//					store->removeUserIdToken(userIdToken);
//					break;
//				}
//				}
//			}
//		} catch (final MslMasterTokenException e) {
//			throw MslInternalException("Unexpected master token exception.", e);
//		} catch (final MslEncodingException e) {
//			throw MslInternalException("Unexpected master token encoding exception.", e);
//		} catch (final MslCryptoException e) {
//			throw MslInternalException("Unexpected master token creation exception.", e);
//		} catch (final MslException e) {
//			throw MslInternalException("Master token / user ID token service token query mismatch.", e);
//		}
//	}
//
//	/** MSL context. */
//	private final MslContext ctx;
//	/** MSL store-> */
//	private final MslStore store;
//	/** Number of master token and user ID token identities. */
//	private final int count;
//}
/*
TEST_F(SimpleMslStoreTest, stressUserIdTokens)
{
	final ExecutorService service = Executors.newCachedThreadPool();
	for (int i = 0; i < 10 * MAX_TOKENS; ++i) {
		service.execute(new UserIdTokenStressor(ctx, store, MAX_TOKENS));
	}
	service.shutdown();
	assertTrue(service.awaitTermination(STRESS_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
}
*/
TEST_F(SimpleMslStoreTest, masterBoundServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	set<shared_ptr<ServiceToken>> tokens = MslTestUtils::getServiceTokens(ctx, masterToken, NULL_USER_ID_TOKEN);

	store->setCryptoContext(masterToken, cryptoContext);

	set<shared_ptr<ServiceToken>> emptyTokens = store->getServiceTokens(masterToken, NULL_USER_ID_TOKEN);
	EXPECT_EQ(static_cast<size_t>(0), emptyTokens.size());

	store->addServiceTokens(tokens);
	set<shared_ptr<ServiceToken>> storedTokens = store->getServiceTokens(masterToken, NULL_USER_ID_TOKEN);
	EXPECT_TRUE(MslTestUtils::equal(tokens, storedTokens));
}

TEST_F(SimpleMslStoreTest, missingMasterTokenAddServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	set<shared_ptr<ServiceToken>> tokens = MslTestUtils::getServiceTokens(ctx, masterToken, NULL_USER_ID_TOKEN);

	try {
		store->addServiceTokens(tokens);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslException& e) {
	}

	set<shared_ptr<ServiceToken>> emptyTokens = store->getServiceTokens(masterToken, NULL_USER_ID_TOKEN);
	EXPECT_EQ(static_cast<size_t>(0), emptyTokens.size());
}

TEST_F(SimpleMslStoreTest, userBoundServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	set<shared_ptr<ServiceToken>> tokens = MslTestUtils::getServiceTokens(ctx, masterToken, userIdToken);

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(USER_ID, userIdToken);

	set<shared_ptr<ServiceToken>> emptyTokens = store->getServiceTokens(masterToken, userIdToken);
	EXPECT_EQ(static_cast<size_t>(0), emptyTokens.size());

	store->addServiceTokens(tokens);
	set<shared_ptr<ServiceToken>> storedTokens = store->getServiceTokens(masterToken, userIdToken);
	EXPECT_TRUE(MslTestUtils::equal(tokens, storedTokens));
}

TEST_F(SimpleMslStoreTest, missingUserIdTokenAddServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	set<shared_ptr<ServiceToken>> tokens = MslTestUtils::getServiceTokens(ctx, masterToken, userIdToken);

	store->setCryptoContext(masterToken, cryptoContext);

	try {
		store->addServiceTokens(tokens);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslException& e) {
	}

	set<shared_ptr<ServiceToken>> emptyTokens = store->getServiceTokens(masterToken, NULL_USER_ID_TOKEN);
	EXPECT_EQ(static_cast<size_t>(0), emptyTokens.size());
}

TEST_F(SimpleMslStoreTest, unboundServiceTokens)
{
	set<shared_ptr<ServiceToken>> tokens = MslTestUtils::getServiceTokens(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);

	set<shared_ptr<ServiceToken>> emptyTokens = store->getServiceTokens(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_EQ(static_cast<size_t>(0), emptyTokens.size());

	store->addServiceTokens(tokens);
	set<shared_ptr<ServiceToken>> storedTokens = store->getServiceTokens(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_TRUE(MslTestUtils::equal(tokens, storedTokens));
}

TEST_F(SimpleMslStoreTest, removeMasterBoundServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	set<shared_ptr<ServiceToken>> masterBoundTokens = MslTestUtils::getMasterBoundServiceTokens(ctx, masterToken);
	set<shared_ptr<ServiceToken>> userBoundTokens = MslTestUtils::getUserBoundServiceTokens(ctx, masterToken, userIdToken);
	set<shared_ptr<ServiceToken>> unboundTokens = MslTestUtils::getServiceTokens(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(USER_ID, userIdToken);
	store->addServiceTokens(masterBoundTokens);
	store->addServiceTokens(userBoundTokens);
	store->addServiceTokens(unboundTokens);

	store->removeServiceTokens(NULL_NAME, masterToken, NULL_USER_ID_TOKEN);

	// This should only return the unbound tokens.
	set<shared_ptr<ServiceToken>> storedMasterBoundTokens = store->getServiceTokens(masterToken, NULL_USER_ID_TOKEN);
	EXPECT_TRUE(MslTestUtils::equal(unboundTokens, storedMasterBoundTokens));

	// This should only return the unbound and user-bound tokens.
	set<shared_ptr<ServiceToken>> unboundAndUserBoundTokens;
	unboundAndUserBoundTokens.insert(unboundTokens.begin(), unboundTokens.end());
	unboundAndUserBoundTokens.insert(userBoundTokens.begin(), userBoundTokens.end());
	set<shared_ptr<ServiceToken>> storedUserBoundTokens = store->getServiceTokens(masterToken, userIdToken);
	EXPECT_TRUE(MslTestUtils::equal(unboundAndUserBoundTokens, storedUserBoundTokens));

	// This should only return the unbound tokens.
	set<shared_ptr<ServiceToken>> storedUnboundTokens = store->getServiceTokens(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_TRUE(MslTestUtils::equal(unboundTokens, storedUnboundTokens));
}

TEST_F(SimpleMslStoreTest, removeUserBoundServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	set<shared_ptr<ServiceToken>> masterBoundTokens = MslTestUtils::getMasterBoundServiceTokens(ctx, masterToken);
	set<shared_ptr<ServiceToken>> userBoundTokens = MslTestUtils::getUserBoundServiceTokens(ctx, masterToken, userIdToken);
	set<shared_ptr<ServiceToken>> unboundTokens = MslTestUtils::getServiceTokens(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(USER_ID, userIdToken);
	store->addServiceTokens(masterBoundTokens);
	store->addServiceTokens(userBoundTokens);
	store->addServiceTokens(unboundTokens);

	store->removeServiceTokens(NULL_NAME, NULL_MASTER_TOKEN, userIdToken);

	// This should only return the unbound and master bound-only tokens.
	set<shared_ptr<ServiceToken>> storedMasterBoundTokens = store->getServiceTokens(masterToken, NULL_USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> unboundAndMasterBoundTokens;
	unboundAndMasterBoundTokens = MslTestUtils::merge(unboundAndMasterBoundTokens, unboundTokens);
	unboundAndMasterBoundTokens = MslTestUtils::merge(unboundAndMasterBoundTokens, masterBoundTokens);
	EXPECT_TRUE(MslTestUtils::equal(unboundAndMasterBoundTokens, storedMasterBoundTokens));

	// This should only return the unbound and master bound-only tokens.
	set<shared_ptr<ServiceToken>> storedUserBoundTokens = store->getServiceTokens(masterToken, userIdToken);
	EXPECT_TRUE(MslTestUtils::equal(unboundAndMasterBoundTokens, storedUserBoundTokens));

	// This should only return the unbound tokens.
	set<shared_ptr<ServiceToken>> storedUnboundTokens = store->getServiceTokens(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_TRUE(MslTestUtils::equal(unboundTokens, storedUnboundTokens));
}

TEST_F(SimpleMslStoreTest, removeNoServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	set<shared_ptr<ServiceToken>> masterBoundTokens = MslTestUtils::getMasterBoundServiceTokens(ctx, masterToken);
	set<shared_ptr<ServiceToken>> userBoundTokens = MslTestUtils::getUserBoundServiceTokens(ctx, masterToken, userIdToken);
	set<shared_ptr<ServiceToken>> unboundTokens = MslTestUtils::getServiceTokens(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(USER_ID, userIdToken);
	store->addServiceTokens(masterBoundTokens);
	store->addServiceTokens(userBoundTokens);
	store->addServiceTokens(unboundTokens);

	store->removeServiceTokens(NULL_NAME, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);

	// This should only return the unbound and master bound tokens.
	set<shared_ptr<ServiceToken>> storedMasterBoundTokens = store->getServiceTokens(masterToken, NULL_USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> unboundAndMasterBoundTokens;
	unboundAndMasterBoundTokens = MslTestUtils::merge(unboundAndMasterBoundTokens, unboundTokens);
	unboundAndMasterBoundTokens = MslTestUtils::merge(unboundAndMasterBoundTokens, masterBoundTokens);
	EXPECT_TRUE(MslTestUtils::equal(unboundAndMasterBoundTokens, storedMasterBoundTokens));

	// This should return all of the tokens.
	set<shared_ptr<ServiceToken>> storedUserBoundTokens = store->getServiceTokens(masterToken, userIdToken);
	set<shared_ptr<ServiceToken>> allTokens;
	allTokens = MslTestUtils::merge(allTokens, unboundTokens);
	allTokens = MslTestUtils::merge(allTokens, userBoundTokens);
	allTokens = MslTestUtils::merge(allTokens, masterBoundTokens);
	EXPECT_TRUE(MslTestUtils::equal(allTokens, storedUserBoundTokens));

	// This should only return the unbound tokens.
	set<shared_ptr<ServiceToken>> storedUnboundTokens = store->getServiceTokens(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_TRUE(MslTestUtils::equal(unboundTokens, storedUnboundTokens));
}

TEST_F(SimpleMslStoreTest, removeNamedServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	set<shared_ptr<ServiceToken>> masterBoundTokens = MslTestUtils::getMasterBoundServiceTokens(ctx, masterToken);
	set<shared_ptr<ServiceToken>> userBoundTokens = MslTestUtils::getUserBoundServiceTokens(ctx, masterToken, userIdToken);
	set<shared_ptr<ServiceToken>> unboundTokens = MslTestUtils::getServiceTokens(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(USER_ID, userIdToken);
	store->addServiceTokens(masterBoundTokens);
	store->addServiceTokens(userBoundTokens);
	store->addServiceTokens(unboundTokens);

	set<shared_ptr<ServiceToken>> allTokens;
	allTokens = MslTestUtils::merge(allTokens, masterBoundTokens);
	allTokens = MslTestUtils::merge(allTokens, userBoundTokens);
	allTokens = MslTestUtils::merge(allTokens, unboundTokens);

	shared_ptr<IRandom> random = ctx->getRandom();
	set<shared_ptr<ServiceToken>> removedTokens;
	for (set<shared_ptr<ServiceToken>>::iterator tokens = allTokens.begin();
		 tokens != allTokens.end();
		 ++tokens)
	{
		if (random->nextBoolean()) continue;
		shared_ptr<ServiceToken> token = *tokens;
		shared_ptr<string> name = make_shared<string>(token->getName());
		store->removeServiceTokens(name, token->isMasterTokenBound() ? masterToken : NULL_MASTER_TOKEN, token->isUserIdTokenBound() ? userIdToken : NULL_USER_ID_TOKEN);
		removedTokens.insert(token);
	}

	// This should only return tokens that haven't been removed.
	set<shared_ptr<ServiceToken>> storedMasterBoundTokens = store->getServiceTokens(masterToken, NULL_USER_ID_TOKEN);
	EXPECT_TRUE(MslTestUtils::equal(storedMasterBoundTokens, MslTestUtils::remove(storedMasterBoundTokens, removedTokens)));

	// This should only return tokens that haven't been removed.
	set<shared_ptr<ServiceToken>> storedUserBoundTokens = store->getServiceTokens(masterToken, userIdToken);
	EXPECT_TRUE(MslTestUtils::equal(storedUserBoundTokens, MslTestUtils::remove(storedUserBoundTokens, removedTokens)));

	// This should only return tokens that haven't been removed.
	set<shared_ptr<ServiceToken>> storedUnboundTokens = store->getServiceTokens(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_TRUE(MslTestUtils::equal(storedUnboundTokens, MslTestUtils::remove(storedUnboundTokens, removedTokens)));
}

TEST_F(SimpleMslStoreTest, clearServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	set<shared_ptr<ServiceToken>> masterBoundTokens = MslTestUtils::getMasterBoundServiceTokens(ctx, masterToken);
	set<shared_ptr<ServiceToken>> userBoundTokens = MslTestUtils::getUserBoundServiceTokens(ctx, masterToken, userIdToken);
	set<shared_ptr<ServiceToken>> unboundTokens = MslTestUtils::getServiceTokens(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(USER_ID, userIdToken);
	store->addServiceTokens(masterBoundTokens);
	store->addServiceTokens(userBoundTokens);
	store->addServiceTokens(unboundTokens);

	store->clearServiceTokens();

	set<shared_ptr<ServiceToken>> storedMasterBoundTokens = store->getServiceTokens(masterToken, NULL_USER_ID_TOKEN);
	EXPECT_EQ(static_cast<size_t>(0), storedMasterBoundTokens.size());
	set<shared_ptr<ServiceToken>> storedUserBoundTokens = store->getServiceTokens(masterToken, userIdToken);
	EXPECT_EQ(static_cast<size_t>(0), storedUserBoundTokens.size());
	set<shared_ptr<ServiceToken>> storedUnboundTokens = store->getServiceTokens(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_EQ(static_cast<size_t>(0), storedUserBoundTokens.size());
}

TEST_F(SimpleMslStoreTest, mismatchedGetServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<MasterToken> mismatchedMasterToken = MslTestUtils::getMasterToken(ctx, 2, 2);

	try {
		store->getServiceTokens(mismatchedMasterToken, userIdToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslException& e) {
		EXPECT_EQ(MslError::USERIDTOKEN_MASTERTOKEN_MISMATCH, e.getError());
	}
}

TEST_F(SimpleMslStoreTest, missingMasterTokenGetServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());

	try {
		store->getServiceTokens(NULL_MASTER_TOKEN, userIdToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslException& e) {
		EXPECT_EQ(MslError::USERIDTOKEN_MASTERTOKEN_NULL, e.getError());
	}
}

TEST_F(SimpleMslStoreTest, mismatchedRemoveServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<MasterToken> mismatchedMasterToken = MslTestUtils::getMasterToken(ctx, 2, 2);

	try {
		store->removeServiceTokens(NULL_NAME, mismatchedMasterToken, userIdToken);
		ADD_FAILURE() << "Should have thrown";
	} catch (const MslException& e) {
		EXPECT_EQ(MslError::USERIDTOKEN_MASTERTOKEN_MISMATCH, e.getError());
	}
}

TEST_F(SimpleMslStoreTest, removeMasterTokenSameSerialNumberServiceTokens)
{
	shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx, 2, 1);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory::USER());
	set<shared_ptr<ServiceToken>> masterBoundServiceTokens = MslTestUtils::getMasterBoundServiceTokens(ctx, masterTokenA);
	set<shared_ptr<ServiceToken>> serviceTokensA = MslTestUtils::getUserBoundServiceTokens(ctx, masterTokenA, userIdTokenA);
	set<shared_ptr<ServiceToken>> serviceTokensB = MslTestUtils::getUserBoundServiceTokens(ctx, masterTokenB, userIdTokenB);

	store->setCryptoContext(masterTokenA, cryptoContext);
	store->setCryptoContext(masterTokenB, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);
	store->addServiceTokens(masterBoundServiceTokens);
	store->addServiceTokens(serviceTokensA);
	store->addServiceTokens(serviceTokensB);

	// We still have a master token with serial number 1 so no service
	// tokens should have been deleted.
	store->removeCryptoContext(masterTokenA);
	set<shared_ptr<ServiceToken>> storedServiceTokensA = store->getServiceTokens(masterTokenB, userIdTokenA);
	set<shared_ptr<ServiceToken>> storedServiceTokensB = store->getServiceTokens(masterTokenB, userIdTokenB);
	set<shared_ptr<ServiceToken>> expectedServiceTokensA(masterBoundServiceTokens);
	expectedServiceTokensA = MslTestUtils::merge(expectedServiceTokensA, serviceTokensA);
	EXPECT_TRUE(MslTestUtils::equal(expectedServiceTokensA, storedServiceTokensA));
	set<shared_ptr<ServiceToken>> expectedServiceTokensB(masterBoundServiceTokens);
	expectedServiceTokensB = MslTestUtils::merge(expectedServiceTokensB, serviceTokensB);
	EXPECT_TRUE(MslTestUtils::equal(expectedServiceTokensB, storedServiceTokensB));
}

TEST_F(SimpleMslStoreTest, removeMasterTokenReissuedServiceTokens)
{
	// Master token B has a new serial number, to invalidate the old master
	// token and its user ID tokens.
	shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx, 1, 2);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory::USER());
	set<shared_ptr<ServiceToken>> masterBoundServiceTokens = MslTestUtils::getMasterBoundServiceTokens(ctx, masterTokenA);
	set<shared_ptr<ServiceToken>> serviceTokensA = MslTestUtils::getUserBoundServiceTokens(ctx, masterTokenA, userIdTokenA);
	set<shared_ptr<ServiceToken>> serviceTokensB = MslTestUtils::getUserBoundServiceTokens(ctx, masterTokenB, userIdTokenB);

	store->setCryptoContext(masterTokenA, cryptoContext);
	store->setCryptoContext(masterTokenB, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);
	store->addServiceTokens(masterBoundServiceTokens);
	store->addServiceTokens(serviceTokensA);
	store->addServiceTokens(serviceTokensB);

	// All of master token A's user ID tokens should be deleted.
	store->removeCryptoContext(masterTokenA);
	EXPECT_TRUE(store->getServiceTokens(masterTokenA, userIdTokenA).empty());
	set<shared_ptr<ServiceToken>> storedServiceTokensB = store->getServiceTokens(masterTokenB, userIdTokenB);
	EXPECT_TRUE(MslTestUtils::equal(serviceTokensB, storedServiceTokensB));
}

TEST_F(SimpleMslStoreTest, clearCryptoContextsServiceTokens)
{
	// Master token B has a new serial number, to invalidate the old master
	// token and its user ID tokens.
	shared_ptr<MasterToken> masterTokenA = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<MasterToken> masterTokenB = MslTestUtils::getMasterToken(ctx, 1, 2);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory::USER());
	set<shared_ptr<ServiceToken>> unboundServiceTokens = MslTestUtils::getServiceTokens(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	set<shared_ptr<ServiceToken>> serviceTokensA = MslTestUtils::getUserBoundServiceTokens(ctx, masterTokenA, userIdTokenA);
	set<shared_ptr<ServiceToken>> serviceTokensB = MslTestUtils::getUserBoundServiceTokens(ctx, masterTokenB, userIdTokenB);

	store->setCryptoContext(masterTokenA, cryptoContext);
	store->setCryptoContext(masterTokenB, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);
	store->addServiceTokens(unboundServiceTokens);
	store->addServiceTokens(serviceTokensA);
	store->addServiceTokens(serviceTokensB);

	// All bound service tokens should be deleted.
	store->clearCryptoContexts();
	EXPECT_TRUE(MslTestUtils::equal(unboundServiceTokens, store->getServiceTokens(masterTokenA, userIdTokenA)));
	EXPECT_TRUE(MslTestUtils::equal(unboundServiceTokens, store->getServiceTokens(masterTokenB, userIdTokenB)));
	set<shared_ptr<ServiceToken>> storedServiceTokens = store->getServiceTokens(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
	EXPECT_TRUE(MslTestUtils::equal(unboundServiceTokens, storedServiceTokens));
}

TEST_F(SimpleMslStoreTest, removeUserIdTokenServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory::USER());
	set<shared_ptr<ServiceToken>> masterBoundServiceTokens = MslTestUtils::getMasterBoundServiceTokens(ctx, masterToken);
	set<shared_ptr<ServiceToken>> serviceTokensA = MslTestUtils::getUserBoundServiceTokens(ctx, masterToken, userIdTokenA);
	set<shared_ptr<ServiceToken>> serviceTokensB = MslTestUtils::getUserBoundServiceTokens(ctx, masterToken, userIdTokenB);

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);
	store->addServiceTokens(masterBoundServiceTokens);
	store->addServiceTokens(serviceTokensA);
	store->addServiceTokens(serviceTokensB);

	// We should still have all the master token bound and user ID token B
	// bound service tokens.
	store->removeUserIdToken(userIdTokenA);
	set<shared_ptr<ServiceToken>> storedServiceTokens = store->getServiceTokens(masterToken, userIdTokenB);
	set<shared_ptr<ServiceToken>> expectedServiceTokens(masterBoundServiceTokens);
	expectedServiceTokens = MslTestUtils::merge(expectedServiceTokens, serviceTokensB);
	EXPECT_TRUE(MslTestUtils::equal(expectedServiceTokens, storedServiceTokens));
}

TEST_F(SimpleMslStoreTest, clearUserIdTokensServiceTokens)
{
	shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, 1, 1);
	shared_ptr<ICryptoContext> cryptoContext = make_shared<NullCryptoContext>();
	const string userIdA = USER_ID + "A";
	const string userIdB = USER_ID + "B";
	shared_ptr<UserIdToken> userIdTokenA = MslTestUtils::getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory::USER());
	shared_ptr<UserIdToken> userIdTokenB = MslTestUtils::getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory::USER());
	set<shared_ptr<ServiceToken>> masterBoundServiceTokens = MslTestUtils::getMasterBoundServiceTokens(ctx, masterToken);
	set<shared_ptr<ServiceToken>> serviceTokensA = MslTestUtils::getUserBoundServiceTokens(ctx, masterToken, userIdTokenA);
	set<shared_ptr<ServiceToken>> serviceTokensB = MslTestUtils::getUserBoundServiceTokens(ctx, masterToken, userIdTokenB);

	store->setCryptoContext(masterToken, cryptoContext);
	store->addUserIdToken(userIdA, userIdTokenA);
	store->addUserIdToken(userIdB, userIdTokenB);
	store->addServiceTokens(masterBoundServiceTokens);
	store->addServiceTokens(serviceTokensA);
	store->addServiceTokens(serviceTokensB);

	// Only the master token bound service tokens should be left.
	store->clearUserIdTokens();
	set<shared_ptr<ServiceToken>> storedServiceTokens = store->getServiceTokens(masterToken, userIdTokenB);
	EXPECT_TRUE(MslTestUtils::equal(masterBoundServiceTokens, storedServiceTokens));
}

/**
 * Service token add/remove stress test runner.
 *
 * Randomly adds or removes service tokens in combinations of unbound,
 * master token bound, and user ID token bound Also iterates through the
 * service tokens.
 */
//private static class ServiceTokenStressor implements Runnable {
//	/**
//	 * Create a new service token stressor.
//	 *
//	 * @param ctx MSL context.
//	 * @param store MSL store->
//	 * @param count the number of master token and user ID tokens to create
//	 *        combinations of.
//	 */
//	public ServiceTokenStressor(final MslContext ctx, final MslStore store, final int count) {
//		this.ctx = ctx;
//		this.store = store;
//		this.count = count;
//	}
//
//	/* (non-Javadoc)
//	 * @see java.lang.Runnable#run()
//	 */
//	@Override
//	public void run() {
//		final Random r = new Random();
//
//		try {
//			for (int i = 0; i < 10 * count; ++i) {
//				final int tokenIndex = r.nextInt(count);
//				shared_ptr<MasterToken> masterToken = MslTestUtils::getMasterToken(ctx, tokenIndex, 1);
//				final long userId = r.nextInt(count);
//				shared_ptr<UserIdToken> userIdToken = MslTestUtils::getUserIdToken(ctx, masterToken, userId, MockEmailPasswordAuthenticationFactory::USER());
//
//				final int option = r.nextInt(6);
//				switch (option) {
//				case 0:
//				{
//					set<shared_ptr<ServiceToken>> tokens = MslTestUtils::getServiceTokens(ctx, NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
//					store->addServiceTokens(tokens);
//					break;
//				}
//				case 1:
//				{
//					store->setCryptoContext(masterToken, new NullCryptoContext());
//					set<shared_ptr<ServiceToken>> tokens = MslTestUtils::getServiceTokens(ctx, masterToken, null);
//					store->addServiceTokens(tokens);
//					break;
//				}
//				case 2:
//				{
//					store->setCryptoContext(masterToken, new NullCryptoContext());
//					store->addUserIdToken(USER_ID + userId, userIdToken);
//					set<shared_ptr<ServiceToken>> tokens = MslTestUtils::getServiceTokens(ctx, masterToken, userIdToken);
//					store->addServiceTokens(tokens);
//					break;
//				}
//				case 3:
//				{
//					store->getServiceTokens(NULL_MASTER_TOKEN, NULL_USER_ID_TOKEN);
//					break;
//				}
//				case 4:
//				{
//					store->getServiceTokens(masterToken, NULL_USER_ID_TOKEN);
//					break;
//				}
//				case 5:
//				{
//					store->getServiceTokens(masterToken, userIdToken);
//					break;
//				}
//				}
//			}
//		} catch (final MslMasterTokenException e) {
//			throw MslInternalException("Unexpected master token exception.", e);
//		} catch (final MslEncodingException e) {
//			throw MslInternalException("Unexpected master token encoding exception.", e);
//		} catch (final MslCryptoException e) {
//			throw MslInternalException("Unexpected master token creation exception.", e);
//		} catch (final MslException e) {
//			throw MslInternalException("Master token / user ID token service token query mismatch.", e);
//		}
//	}
//
//	/** MSL context. */
//	private final MslContext ctx;
//	/** MSL store. */
//	private final MslStore store;
//	/** Number of master token and user ID token identities. */
//	private final int count;
//}
/*
TEST_F(SimpleMslStoreTest, stressServiceTokens)
{
	final ExecutorService service = Executors.newCachedThreadPool();
	for (int i = 0; i < 10 * MAX_TOKENS; ++i) {
		service.execute(new ServiceTokenStressor(ctx, store, MAX_TOKENS));
	}
	service.shutdown();
	assertTrue(service.awaitTermination(STRESS_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
}
*/

}}} // namespace netflix::msl::util
