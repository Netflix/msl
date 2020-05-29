/**
 * Copyright (c) 2012-2020 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.msg;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.AsymmetricWrappedExchange.RequestData.Mechanism;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.DiffieHellmanParameters;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.keyx.MockDiffieHellmanParameters;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.keyx.SymmetricWrappedExchange.KeyId;
import com.netflix.msl.msg.MessageHeader.HeaderData;
import com.netflix.msl.msg.MessageHeader.HeaderPeerData;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.MslTestUtils;

/**
 * Message builder unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({MessageBuilderSuite.Tests.class,
               MessageBuilderSuite.CreateRequestTest.class,
               MessageBuilderSuite.CreateErrorTest.class,
               MessageBuilderSuite.CreateResponseTest.class})
public class MessageBuilderSuite {
    private static final String SERVICE_TOKEN_NAME = "serviceTokenName";
    private static final String USER_ID = "userid";
    private static final String PEER_USER_ID = "peeruserid";
    private static final String PARAMETERS_ID = MockDiffieHellmanParameters.DEFAULT_ID;
    
    /** Random. */
    private static Random random;
    /** MSL trusted network context. */
    private static MslContext trustedNetCtx;
    /** MSL peer-to-peer context. */
    private static MslContext p2pCtx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Message Factory. */
    private static MessageFactory messageFactory = new MessageFactory();
    
    private static MasterToken MASTER_TOKEN, PEER_MASTER_TOKEN;
    private static ICryptoContext CRYPTO_CONTEXT, ALT_MSL_CRYPTO_CONTEXT;
    private static UserIdToken USER_ID_TOKEN, PEER_USER_ID_TOKEN;
    private static UserAuthenticationData USER_AUTH_DATA;
    private static final Set<KeyRequestData> KEY_REQUEST_DATA = new HashSet<KeyRequestData>();
    private static final Set<KeyRequestData> PEER_KEY_REQUEST_DATA = new HashSet<KeyRequestData>();
    
    @BeforeClass
    public static synchronized void setup() throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslMasterTokenException, MslEntityAuthException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        if (random == null) {
            random = new Random();
            trustedNetCtx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            p2pCtx = new MockMslContext(EntityAuthenticationScheme.PSK, true);
            encoder = trustedNetCtx.getMslEncoderFactory();
            
            USER_AUTH_DATA = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
            
            MASTER_TOKEN = MslTestUtils.getMasterToken(trustedNetCtx, 1, 1);
            USER_ID_TOKEN = MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
            CRYPTO_CONTEXT = new NullCryptoContext();
            
            final DiffieHellmanParameters params = MockDiffieHellmanParameters.getDefaultParameters();
            final DHParameterSpec paramSpec = params.getParameterSpec(MockDiffieHellmanParameters.DEFAULT_ID);
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
            
            generator.initialize(paramSpec);
            final KeyPair requestKeyPair = generator.generateKeyPair();
            final BigInteger publicKey = ((DHPublicKey)requestKeyPair.getPublic()).getY();
            final DHPrivateKey privateKey = (DHPrivateKey)requestKeyPair.getPrivate();
            
            KEY_REQUEST_DATA.add(new DiffieHellmanExchange.RequestData(PARAMETERS_ID, publicKey, privateKey));
            KEY_REQUEST_DATA.add(new SymmetricWrappedExchange.RequestData(KeyId.SESSION));
            KEY_REQUEST_DATA.add(new SymmetricWrappedExchange.RequestData(KeyId.PSK));
            
            PEER_MASTER_TOKEN = MslTestUtils.getMasterToken(p2pCtx, 1, 2);
            PEER_USER_ID_TOKEN = MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
            
            final KeyRequestData peerKeyRequestData = new SymmetricWrappedExchange.RequestData(KeyId.SESSION);
            PEER_KEY_REQUEST_DATA.add(peerKeyRequestData);
            PEER_KEY_REQUEST_DATA.add(new SymmetricWrappedExchange.RequestData(KeyId.PSK));
            
            final byte[] mke = new byte[16];
            final byte[] mkh = new byte[32];
            final byte[] mkw = new byte[16];
            random.nextBytes(mke);
            random.nextBytes(mkh);
            random.nextBytes(mkw);
            final SecretKey encryptionKey = new SecretKeySpec(mke, JcaAlgorithm.AES);
            final SecretKey hmacKey = new SecretKeySpec(mkh, JcaAlgorithm.HMAC_SHA256);
            final SecretKey wrappingKey = new SecretKeySpec(mkw, JcaAlgorithm.AESKW);
            ALT_MSL_CRYPTO_CONTEXT = new SymmetricCryptoContext(trustedNetCtx, "clientMslCryptoContext", encryptionKey, hmacKey, wrappingKey);
        }
    }
    
    @AfterClass
    public static synchronized void teardown() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    }
    
    /** Common tests. */
    public static class Tests {
        @Test
        public void incrementMessageId() {
            final long one = MessageBuilder.incrementMessageId(0);
            assertEquals(1, one);

            final long zero = MessageBuilder.incrementMessageId(MslConstants.MAX_LONG_VALUE);
            assertEquals(0, zero);

            for (int i = 0; i < 1000; ++i) {
                long initial = -1;
                do {
                    initial = random.nextLong();
                } while (initial < 0 || initial > MslConstants.MAX_LONG_VALUE);
                final long next = MessageBuilder.incrementMessageId(initial);
                assertEquals((initial != MslConstants.MAX_LONG_VALUE) ? initial + 1 : 0, next);
            }
        }

        @Test(expected = MslInternalException.class)
        public void incrementNegativeMessageId() {
            MessageBuilder.incrementMessageId(-1);
        }

        @Test(expected = MslInternalException.class)
        public void incrementTooLargeMessageId() {
            MessageBuilder.incrementMessageId(MslConstants.MAX_LONG_VALUE + 1);
        }

        @Test
        public void decrementMessageId() {
            final long max = MessageBuilder.decrementMessageId(0);
            assertEquals(MslConstants.MAX_LONG_VALUE, max);

            final long max_m1 = MessageBuilder.decrementMessageId(MslConstants.MAX_LONG_VALUE);
            assertEquals(MslConstants.MAX_LONG_VALUE - 1, max_m1);

            for (int i = 0; i < 1000; ++i) {
                long initial = -1;
                do {
                    initial = random.nextLong();
                } while (initial < 0 || initial > MslConstants.MAX_LONG_VALUE);
                final long next = MessageBuilder.decrementMessageId(initial);
                assertEquals((initial != 0) ? initial - 1 : MslConstants.MAX_LONG_VALUE, next);
            }
        }

        @Test(expected = MslInternalException.class)
        public void decrementNegativeMessageId() {
            MessageBuilder.decrementMessageId(-1);
        }

        @Test(expected = MslInternalException.class)
        public void decrementTooLargeMessageId() {
            MessageBuilder.decrementMessageId(MslConstants.MAX_LONG_VALUE + 1);
        }
    }
    
    /** Create request unit tests. */
    public static class CreateRequestTest {
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Before
        public void reset() {
            trustedNetCtx.getMslStore().clearCryptoContexts();
            trustedNetCtx.getMslStore().clearServiceTokens();
            p2pCtx.getMslStore().clearCryptoContexts();
            p2pCtx.getMslStore().clearServiceTokens();
        }
        
        @Test
        public void createNullRequest() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, null, null);
            assertTrue(builder.willEncryptHeader());
            assertTrue(builder.willEncryptPayloads());
            assertTrue(builder.willIntegrityProtectHeader());
            assertTrue(builder.willIntegrityProtectPayloads());
            final MessageHeader header = builder.getHeader();
            assertNotNull(header);

            assertNull(header.getNonReplayableId());
            assertFalse(header.isRenewable());
            assertFalse(header.isHandshake());
            assertNotNull(header.getCryptoContext());
            assertEquals(trustedNetCtx.getEntityAuthenticationData(null), header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().isEmpty());
            assertNull(header.getKeyResponseData());
            assertNull(header.getMasterToken());
            assertTrue(header.getMessageId() >= 0);
            assertEquals(trustedNetCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNull(header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().isEmpty());
            assertNull(header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().isEmpty());
            assertNull(header.getUserAuthenticationData());
            assertNull(header.getUserIdToken());
        }
    
        @Test
        public void createNullPeerRequest() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, null, null);
            assertTrue(builder.willEncryptHeader());
            assertTrue(builder.willEncryptPayloads());
            assertTrue(builder.willIntegrityProtectHeader());
            assertTrue(builder.willIntegrityProtectPayloads());
            final MessageHeader header = builder.getHeader();
            assertNotNull(header);
            
            assertNull(header.getNonReplayableId());
            assertFalse(header.isRenewable());
            assertFalse(header.isHandshake());
            assertNotNull(header.getCryptoContext());
            assertEquals(p2pCtx.getEntityAuthenticationData(null), header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().isEmpty());
            assertNull(header.getKeyResponseData());
            assertNull(header.getMasterToken());
            assertTrue(header.getMessageId() >= 0);
            assertEquals(p2pCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNull(header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().isEmpty());
            assertNull(header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().isEmpty());
            assertNull(header.getUserAuthenticationData());
            assertNull(header.getUserIdToken());
        }
        
        @Test
        public void createRequest() throws MslException {
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                builder.addKeyRequestData(keyRequestData);
            for (final ServiceToken serviceToken : serviceTokens)
                builder.addServiceToken(serviceToken);
            builder.setNonReplayable(true);
            builder.setRenewable(true);
            assertTrue(builder.willEncryptHeader());
            assertTrue(builder.willEncryptPayloads());
            assertTrue(builder.willIntegrityProtectHeader());
            assertTrue(builder.willIntegrityProtectPayloads());
            assertEquals(serviceTokens, builder.getServiceTokens());
            assertTrue(builder.getPeerServiceTokens().isEmpty());
            
            final MessageHeader header = builder.getHeader();
            assertNotNull(header);

            assertNotNull(header.getNonReplayableId());
            assertTrue(header.isRenewable());
            assertFalse(header.isHandshake());
            assertNotNull(header.getCryptoContext());
            assertNull(header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().equals(KEY_REQUEST_DATA));
            assertNull(header.getKeyResponseData());
            assertEquals(MASTER_TOKEN, header.getMasterToken());
            assertTrue(header.getMessageId() >= 0);
            assertEquals(trustedNetCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNotNull(header.getNonReplayableId());
            assertNull(header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().isEmpty());
            assertNull(header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().equals(serviceTokens));
            assertNull(header.getUserAuthenticationData());
            assertEquals(USER_ID_TOKEN, header.getUserIdToken());
        }
        
        @Test
        public void createRequestWithMessageId() throws MslEncodingException, MslCryptoException, MslMessageException, MslMasterTokenException, MslEntityAuthException, MslException {
            final long messageId = 17;
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN, messageId);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                builder.addKeyRequestData(keyRequestData);
            for (final ServiceToken serviceToken : serviceTokens)
                builder.addServiceToken(serviceToken);
            builder.setNonReplayable(true);
            builder.setRenewable(true);
            assertTrue(builder.willEncryptHeader());
            assertTrue(builder.willEncryptPayloads());
            assertTrue(builder.willIntegrityProtectHeader());
            assertTrue(builder.willIntegrityProtectPayloads());
            assertEquals(serviceTokens, builder.getServiceTokens());
            assertTrue(builder.getPeerServiceTokens().isEmpty());
            
            final MessageHeader header = builder.getHeader();
            assertNotNull(header);
            
            assertTrue(header.isRenewable());
            assertFalse(header.isHandshake());
            assertNotNull(header.getCryptoContext());
            assertNull(header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().equals(KEY_REQUEST_DATA));
            assertNull(header.getKeyResponseData());
            assertEquals(MASTER_TOKEN, header.getMasterToken());
            assertEquals(messageId, header.getMessageId());
            assertEquals(trustedNetCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNotNull(header.getNonReplayableId());
            assertNull(header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().isEmpty());
            assertNull(header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().equals(serviceTokens));
            assertNull(header.getUserAuthenticationData());
            assertEquals(USER_ID_TOKEN, header.getUserIdToken());
        }
        
        @Test
        public void createPeerRequest() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                builder.addKeyRequestData(keyRequestData);
            for (final ServiceToken serviceToken : serviceTokens)
                builder.addServiceToken(serviceToken);
            builder.setNonReplayable(true);
            builder.setRenewable(true);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            for (final ServiceToken peerServiceToken : peerServiceTokens)
                builder.addPeerServiceToken(peerServiceToken);
            assertTrue(builder.willEncryptHeader());
            assertTrue(builder.willEncryptPayloads());
            assertTrue(builder.willIntegrityProtectHeader());
            assertTrue(builder.willIntegrityProtectPayloads());
            assertEquals(serviceTokens, builder.getServiceTokens());
            assertEquals(peerServiceTokens, builder.getPeerServiceTokens());
            
            final MessageHeader header = builder.getHeader();
            assertNotNull(header);
            
            assertTrue(header.isRenewable());
            assertFalse(header.isHandshake());
            assertNotNull(header.getCryptoContext());
            assertNull(header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().equals(KEY_REQUEST_DATA));
            assertNull(header.getKeyResponseData());
            assertEquals(MASTER_TOKEN, header.getMasterToken());
            assertTrue(header.getMessageId() >= 0);
            assertEquals(p2pCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNotNull(header.getNonReplayableId());
            assertEquals(PEER_MASTER_TOKEN, header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().equals(peerServiceTokens));
            assertEquals(PEER_USER_ID_TOKEN, header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().equals(serviceTokens));
            assertNull(header.getUserAuthenticationData());
            assertEquals(USER_ID_TOKEN, header.getUserIdToken());
        }
        
        @Test
        public void createHandshakeRequest() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, null, null);
            builder.setNonReplayable(true);
            builder.setRenewable(false);
            builder.setHandshake(true);
            assertFalse(builder.isNonReplayable());
            assertTrue(builder.isHandshake());
            assertTrue(builder.isRenewable());
            final MessageHeader header = builder.getHeader();
            assertNotNull(header);
            
            assertTrue(header.isRenewable());
            assertTrue(header.isHandshake());
            assertNotNull(header.getCryptoContext());
            assertEquals(trustedNetCtx.getEntityAuthenticationData(null), header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().isEmpty());
            assertNull(header.getKeyResponseData());
            assertNull(header.getMasterToken());
            assertTrue(header.getMessageId() >= 0);
            assertEquals(trustedNetCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNull(header.getNonReplayableId());
            assertNull(header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().isEmpty());
            assertNull(header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().isEmpty());
            assertNull(header.getUserAuthenticationData());
            assertNull(header.getUserIdToken());
        }
        
        @Test
        public void createPeerHandshakeRequest() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, null, null);
            builder.setNonReplayable(true);
            builder.setRenewable(false);
            builder.setHandshake(true);
            assertFalse(builder.isNonReplayable());
            assertTrue(builder.isHandshake());
            assertTrue(builder.isRenewable());
            final MessageHeader header = builder.getHeader();
            assertNotNull(header);
            
            assertNull(header.getNonReplayableId());
            assertTrue(header.isRenewable());
            assertTrue(header.isHandshake());
            assertNotNull(header.getCryptoContext());
            assertEquals(p2pCtx.getEntityAuthenticationData(null), header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().isEmpty());
            assertNull(header.getKeyResponseData());
            assertNull(header.getMasterToken());
            assertTrue(header.getMessageId() >= 0);
            assertEquals(p2pCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNull(header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().isEmpty());
            assertNull(header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().isEmpty());
            assertNull(header.getUserAuthenticationData());
            assertNull(header.getUserIdToken());
        }
        
        @Test
        public void willEncryptX509EntityAuth() throws MslException {
            final MslContext x509Ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
            final MessageBuilder builder = messageFactory.createRequest(x509Ctx, null, null);
            assertFalse(builder.willEncryptHeader());
            assertFalse(builder.willEncryptPayloads());
            assertTrue(builder.willIntegrityProtectHeader());
            assertTrue(builder.willIntegrityProtectPayloads());
        }
        
        @Test
        public void willIntegrityProtectNoneAuth() throws MslException {
            final MslContext noneCtx = new MockMslContext(EntityAuthenticationScheme.NONE, false);
            final MessageBuilder builder = messageFactory.createRequest(noneCtx, null, null);
            assertFalse(builder.willEncryptHeader());
            assertFalse(builder.willEncryptPayloads());
            assertFalse(builder.willIntegrityProtectHeader());
            assertFalse(builder.willIntegrityProtectPayloads());
        }
        
        @Test
        public void storedServiceTokens() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MslStore store = trustedNetCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(USER_ID, USER_ID_TOKEN);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            // The message will include all unbound service tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }
            
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            assertEquals(updatedServiceTokens, builder.getServiceTokens());
            assertTrue(builder.getPeerServiceTokens().isEmpty());
            final MessageHeader header = builder.getHeader();
            
            assertTrue(header.getServiceTokens().equals(updatedServiceTokens));
            assertTrue(header.getPeerServiceTokens().isEmpty());
        }
        
        @Test
        public void storedPeerServiceTokens() throws MslEncodingException, MslCryptoException, MslMessageException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MslStore store = p2pCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(USER_ID, USER_ID_TOKEN);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            // The non-peer service tokens will include all unbound service
            // tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }
            
            // The peer service tokens will include all unbound service tokens.
            final Set<ServiceToken> updatedPeerServiceTokens = new HashSet<ServiceToken>(peerServiceTokens);
            for (final ServiceToken serviceToken : serviceTokens) {
                if (serviceToken.isUnbound())
                    updatedPeerServiceTokens.add(serviceToken);
            }
            
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            assertEquals(updatedServiceTokens, builder.getServiceTokens());
            assertEquals(updatedPeerServiceTokens, builder.getPeerServiceTokens());
            final MessageHeader header = builder.getHeader();
            
            assertTrue(header.getServiceTokens().equals(updatedServiceTokens));
            assertTrue(header.getPeerServiceTokens().equals(updatedPeerServiceTokens));
        }
        
        @Test
        public void setUserAuthData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            // Setting the user authentication data will replace the user ID token
            // and remove any user ID token bound service tokens.
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                builder.addKeyRequestData(keyRequestData);
            for (final ServiceToken serviceToken : serviceTokens)
                builder.addServiceToken(serviceToken);
            builder.setNonReplayable(true);
            builder.setRenewable(true);
            builder.setUserAuthenticationData(USER_AUTH_DATA);
            
            assertEquals(serviceTokens, builder.getServiceTokens());
            assertTrue(builder.getPeerServiceTokens().isEmpty());
            final MessageHeader header = builder.getHeader();
            
            assertNotNull(header.getNonReplayableId());
            assertTrue(header.isRenewable());
            assertNotNull(header.getCryptoContext());
            assertNull(header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().equals(KEY_REQUEST_DATA));
            assertNull(header.getKeyResponseData());
            assertEquals(MASTER_TOKEN, header.getMasterToken());
            assertTrue(header.getMessageId() >= 0);
            assertEquals(trustedNetCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNull(header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().isEmpty());
            assertNull(header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().equals(serviceTokens));
            assertEquals(USER_AUTH_DATA, header.getUserAuthenticationData());
            assertEquals(USER_ID_TOKEN, header.getUserIdToken());
        }
        
        @Test
        public void setUserAuthDataNull() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                builder.addKeyRequestData(keyRequestData);
            for (final ServiceToken serviceToken : serviceTokens)
                builder.addServiceToken(serviceToken);
            builder.setNonReplayable(true);
            builder.setRenewable(true);
            builder.setUserAuthenticationData(null);
            assertEquals(serviceTokens, builder.getServiceTokens());
            assertTrue(builder.getPeerServiceTokens().isEmpty());
            final MessageHeader header = builder.getHeader();
            
            assertNotNull(header.getNonReplayableId());
            assertTrue(header.isRenewable());
            assertNotNull(header.getCryptoContext());
            assertNull(header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().equals(KEY_REQUEST_DATA));
            assertNull(header.getKeyResponseData());
            assertEquals(MASTER_TOKEN, header.getMasterToken());
            assertTrue(header.getMessageId() >= 0);
            assertEquals(trustedNetCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNull(header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().isEmpty());
            assertNull(header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().equals(serviceTokens));
            assertNull(header.getUserAuthenticationData());
            assertEquals(USER_ID_TOKEN, header.getUserIdToken());
        }
        
        @Test
        public void unsetUserAuthData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                builder.addKeyRequestData(keyRequestData);
            for (final ServiceToken serviceToken : serviceTokens)
                builder.addServiceToken(serviceToken);
            builder.setNonReplayable(true);
            builder.setRenewable(true);
            builder.setUserAuthenticationData(USER_AUTH_DATA);
            builder.setUserAuthenticationData(null);

            assertEquals(serviceTokens, builder.getServiceTokens());
            assertTrue(builder.getPeerServiceTokens().isEmpty());
            final MessageHeader header = builder.getHeader();
            
            assertNotNull(header.getNonReplayableId());
            assertTrue(header.isRenewable());
            assertNotNull(header.getCryptoContext());
            assertNull(header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().equals(KEY_REQUEST_DATA));
            assertNull(header.getKeyResponseData());
            assertEquals(MASTER_TOKEN, header.getMasterToken());
            assertTrue(header.getMessageId() >= 0);
            assertEquals(trustedNetCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNull(header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().isEmpty());
            assertNull(header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().equals(serviceTokens));
            assertNull(header.getUserAuthenticationData());
            assertEquals(USER_ID_TOKEN, header.getUserIdToken());
        }
        
        @Test
        public void overwriteKeyRequestData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, null, null);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                builder.addKeyRequestData(keyRequestData);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                builder.addKeyRequestData(keyRequestData);
            final MessageHeader header = builder.getHeader();

            assertNull(header.getNonReplayableId());
            assertFalse(header.isRenewable());
            assertNotNull(header.getCryptoContext());
            assertEquals(trustedNetCtx.getEntityAuthenticationData(null), header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().equals(KEY_REQUEST_DATA));
            assertNull(header.getKeyResponseData());
            assertNull(header.getMasterToken());
            assertTrue(header.getMessageId() >= 0);
            assertEquals(trustedNetCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNull(header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().isEmpty());
            assertNull(header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().isEmpty());
            assertNull(header.getUserAuthenticationData());
            assertNull(header.getUserIdToken());
        }
        
        @Test
        public void removeKeyRequestData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, null, null);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                builder.addKeyRequestData(keyRequestData);
            final KeyRequestData keyRequestData = KEY_REQUEST_DATA.toArray(new KeyRequestData[0])[0];
            final Set<KeyRequestData> updatedKeyRequestData = new HashSet<KeyRequestData>(KEY_REQUEST_DATA);
            updatedKeyRequestData.remove(keyRequestData);
            builder.removeKeyRequestData(keyRequestData);
            builder.removeKeyRequestData(keyRequestData);
            final MessageHeader header = builder.getHeader();

            assertNull(header.getNonReplayableId());
            assertFalse(header.isRenewable());
            assertNotNull(header.getCryptoContext());
            assertEquals(trustedNetCtx.getEntityAuthenticationData(null), header.getEntityAuthenticationData());
            assertTrue(header.getKeyRequestData().equals(updatedKeyRequestData));
            assertNull(header.getKeyResponseData());
            assertNull(header.getMasterToken());
            assertTrue(header.getMessageId() >= 0);
            assertEquals(trustedNetCtx.getMessageCapabilities(), header.getMessageCapabilities());
            assertNull(header.getPeerMasterToken());
            assertTrue(header.getPeerServiceTokens().isEmpty());
            assertNull(header.getPeerUserIdToken());
            assertTrue(header.getServiceTokens().isEmpty());
            assertNull(header.getUserAuthenticationData());
            assertNull(header.getUserIdToken());
        }
        
        @Test
        public void nonReplayableMissingMasterToken() throws MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.NONREPLAYABLE_MESSAGE_REQUIRES_MASTERTOKEN);

            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, null, null);
            builder.setNonReplayable(true);
            builder.getHeader();
        }
        
        @Test
        public void mismatchedMasterTokenAddTokenServiceToken() throws MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH);

            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null);
            final byte[] data = new byte[1];
            random.nextBytes(data);
            final ServiceToken serviceToken = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext());
            builder.addServiceToken(serviceToken);
        }
        
        @Test
        public void nullMasterTokenAddServiceToken() throws MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH);

            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, null, null);
            final byte[] data = new byte[1];
            random.nextBytes(data);
            final ServiceToken serviceToken = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, null, false, null, new NullCryptoContext());
            builder.addServiceToken(serviceToken);
        }
        
        @Test
        public void mismatchedUserIdTokenAddServiceToken() throws MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH);

            final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
            final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(trustedNetCtx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, userIdTokenA);
            final byte[] data = new byte[1];
            random.nextBytes(data);
            final ServiceToken serviceToken = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, userIdTokenB, false, null, new NullCryptoContext());
            builder.addServiceToken(serviceToken);
        }
        
        @Test
        public void nullUserIdTokenAddServiceToken() throws MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH);
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null);
            final byte[] data = new byte[1];
            random.nextBytes(data);
            final ServiceToken serviceToken = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext());
            builder.addServiceToken(serviceToken);
        }
        
        @Test
        public void addNamedServiceTokens() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final byte[] data = new byte[1];
            random.nextBytes(data);
            
            final ServiceToken unboundServiceTokenA = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, null, null, false, null, new NullCryptoContext());
            builder.addServiceToken(unboundServiceTokenA);
            assertEquals(1, builder.getServiceTokens().size());
            
            final ServiceToken unboundServiceTokenB = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, null, null, false, null, new NullCryptoContext());
            builder.addServiceToken(unboundServiceTokenB);
            assertEquals(1, builder.getServiceTokens().size());
            
            final ServiceToken masterBoundServiceTokenA = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, null, false, null, new NullCryptoContext());
            builder.addServiceToken(masterBoundServiceTokenA);
            assertEquals(2, builder.getServiceTokens().size());
            
            final ServiceToken masterBoundServiceTokenB = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, null, false, null, new NullCryptoContext());
            builder.addServiceToken(masterBoundServiceTokenB);
            assertEquals(2, builder.getServiceTokens().size());
            
            final ServiceToken userBoundServiceTokenA = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext());
            builder.addServiceToken(userBoundServiceTokenA);
            assertEquals(3, builder.getServiceTokens().size());
            
            final ServiceToken userBoundServiceTokenB = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext());
            builder.addServiceToken(userBoundServiceTokenB);
            assertEquals(3, builder.getServiceTokens().size());
        }
        
        @Test
        public void excludeServiceToken() throws MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);

            for (final ServiceToken serviceToken : serviceTokens)
                builder.addServiceToken(serviceToken);
            
            final Iterator<ServiceToken> tokens = serviceTokens.iterator();
            while (tokens.hasNext()) {
                final ServiceToken token = tokens.next();
                
                builder.excludeServiceToken(token.getName(), token.isMasterTokenBound(), token.isUserIdTokenBound());
                tokens.remove();
                final MessageHeader messageHeader = builder.getHeader();
                assertTrue(messageHeader.getServiceTokens().equals(serviceTokens));
            }
        }
        
        @Test
        public void excludeServiceTokenAlternate() throws MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);

            for (final ServiceToken serviceToken : serviceTokens)
                builder.addServiceToken(serviceToken);
            
            final Iterator<ServiceToken> tokens = serviceTokens.iterator();
            while (tokens.hasNext()) {
                final ServiceToken token = tokens.next();
                
                builder.excludeServiceToken(token);
                tokens.remove();
                final MessageHeader messageHeader = builder.getHeader();
                assertTrue(messageHeader.getServiceTokens().equals(serviceTokens));
            }
        }
        
        @Test
        public void deleteServiceToken() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            
            // The service token must exist before it can be deleted.
            final byte[] data = new byte[1];
            random.nextBytes(data);
            final ServiceToken serviceToken = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext());
            builder.addServiceToken(serviceToken);
            
            // Delete the service token.
            builder.deleteServiceToken(SERVICE_TOKEN_NAME, true, true);
            final MessageHeader messageHeader = builder.getHeader();
            final Set<ServiceToken> tokens = messageHeader.getServiceTokens();
            for (final ServiceToken token : tokens) {
                if (token.getName().equals(SERVICE_TOKEN_NAME)) {
                    assertEquals(0, token.getData().length);
                    return;
                }
            }
            
            fail("Deleted service token not found.");
        }
        
        @Test
        public void deleteServiceTokenAlternate() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            
            // The service token must exist before it can be deleted.
            final byte[] data = new byte[1];
            random.nextBytes(data);
            final ServiceToken serviceToken = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, data, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext());
            builder.addServiceToken(serviceToken);
            
            // Delete the service token.
            builder.deleteServiceToken(serviceToken);
            final MessageHeader messageHeader = builder.getHeader();
            final Set<ServiceToken> tokens = messageHeader.getServiceTokens();
            for (final ServiceToken token : tokens) {
                if (token.getName().equals(SERVICE_TOKEN_NAME)) {
                    assertEquals(0, token.getData().length);
                    return;
                }
            }
            
            fail("Deleted service token not found.");
        }
        
        @Test
        public void deleteUnknownServiceToken() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.deleteServiceToken(SERVICE_TOKEN_NAME, true, true);
            final MessageHeader messageHeader = builder.getHeader();
            final Set<ServiceToken> tokens = messageHeader.getServiceTokens();
            for (final ServiceToken token : tokens) {
                if (token.getName().equals(SERVICE_TOKEN_NAME)) {
                    assertEquals(0, token.getData().length);
                    return;
                }
            }
            fail("Deleted unknown service token not found.");
        }
        
        @Test(expected = MslInternalException.class)
        public void notP2PCreatePeerRequest() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            
        }
        
        @Test(expected = MslInternalException.class)
        public void missingPeerMasterTokenCreatePeerRequest() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(null, PEER_USER_ID_TOKEN);
            
        }
        
        @Test(expected = MslException.class)
        public void mismatchedPeerMasterTokenCreatePeerRequest() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(MASTER_TOKEN, PEER_USER_ID_TOKEN);
        }
        
        @Test(expected = MslInternalException.class)
        public void notP2PAddPeerServiceToken() throws MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final ServiceToken peerServiceToken = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, new byte[0], null, null, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(peerServiceToken);
        }
        
        @Test
        public void missingPeerMasterTokenAddPeerServiceToken() throws MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH);

            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final ServiceToken peerServiceToken = new ServiceToken(p2pCtx, SERVICE_TOKEN_NAME, new byte[0], PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(peerServiceToken);
        }
        
        @Test
        public void mismatchedPeerMasterTokenAddPeerServiceToken() throws MslEncodingException, MslCryptoException, MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH);

            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            final ServiceToken peerServiceToken = new ServiceToken(trustedNetCtx, SERVICE_TOKEN_NAME, new byte[0], MASTER_TOKEN, null, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(peerServiceToken);
        }
        
        @Test
        public void missingPeerUserIdTokenAddPeerServiceToken() throws MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH);

            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
            final ServiceToken peerServiceToken = new ServiceToken(p2pCtx, SERVICE_TOKEN_NAME, new byte[0], PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(peerServiceToken);
        }
        
        @Test
        public void mismatchedPeerUserIdTokenAddPeerServiceToken() throws MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.SERVICETOKEN_USERIDTOKEN_MISMATCH);

            final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
            final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, userIdTokenA);
            final ServiceToken peerServiceToken = new ServiceToken(p2pCtx, SERVICE_TOKEN_NAME, new byte[0], PEER_MASTER_TOKEN, userIdTokenB, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(peerServiceToken);
        }
        
        @Test
        public void addNamedPeerServiceTokens() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            final byte[] data = new byte[1];
            random.nextBytes(data);
            
            final ServiceToken unboundServiceTokenA = new ServiceToken(p2pCtx, SERVICE_TOKEN_NAME, data, null, null, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(unboundServiceTokenA);
            assertEquals(1, builder.getPeerServiceTokens().size());
            
            final ServiceToken unboundServiceTokenB = new ServiceToken(p2pCtx, SERVICE_TOKEN_NAME, data, null, null, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(unboundServiceTokenB);
            assertEquals(1, builder.getPeerServiceTokens().size());
            
            final ServiceToken masterBoundServiceTokenA = new ServiceToken(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(masterBoundServiceTokenA);
            assertEquals(2, builder.getPeerServiceTokens().size());
            
            final ServiceToken masterBoundServiceTokenB = new ServiceToken(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(masterBoundServiceTokenB);
            assertEquals(2, builder.getPeerServiceTokens().size());
            
            final ServiceToken userBoundServiceTokenA = new ServiceToken(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(userBoundServiceTokenA);
            assertEquals(3, builder.getPeerServiceTokens().size());
            
            final ServiceToken userBoundServiceTokenB = new ServiceToken(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(userBoundServiceTokenB);
            assertEquals(3, builder.getPeerServiceTokens().size());
        }
        
        @Test
        public void excludePeerServiceToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            for (final ServiceToken serviceToken : serviceTokens)
                builder.addPeerServiceToken(serviceToken);
            
            final Iterator<ServiceToken> tokens = serviceTokens.iterator();
            while (tokens.hasNext()) {
                final ServiceToken token = tokens.next();
                builder.excludePeerServiceToken(token.getName(), token.isMasterTokenBound(), token.isUserIdTokenBound());
                tokens.remove();
                assertEquals(serviceTokens, builder.getPeerServiceTokens());
                final MessageHeader messageHeader = builder.getHeader();
                assertEquals(serviceTokens, messageHeader.getPeerServiceTokens());
            }
        }
        
        @Test
        public void excludePeerServiceTokenAlternate() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            for (final ServiceToken serviceToken : serviceTokens)
                builder.addPeerServiceToken(serviceToken);
            
            final Iterator<ServiceToken> tokens = serviceTokens.iterator();
            while (tokens.hasNext()) {
                final ServiceToken token = tokens.next();
                builder.excludePeerServiceToken(token);
                tokens.remove();
                assertEquals(serviceTokens, builder.getPeerServiceTokens());
                final MessageHeader messageHeader = builder.getHeader();
                assertEquals(serviceTokens, messageHeader.getPeerServiceTokens());
            }
        }
        
        @Test
        public void deletePeerServiceToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            
            // The service token must exist before it can be deleted.
            final byte[] data = new byte[1];
            random.nextBytes(data);
            final ServiceToken serviceToken = new ServiceToken(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(serviceToken);
            
            // Delete the service token.
            builder.deletePeerServiceToken(SERVICE_TOKEN_NAME, true, true);
            final MessageHeader messageHeader = builder.getHeader();
            final Set<ServiceToken> tokens = messageHeader.getPeerServiceTokens();
            for (final ServiceToken token : tokens) {
                if (token.getName().equals(SERVICE_TOKEN_NAME)) {
                    assertEquals(0, token.getData().length);
                    return;
                }
            }
            fail("Deleted peer service token not found.");
        }
        
        @Test
        public void deletePeerServiceTokenAlternate() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            
            // The service token must exist before it can be deleted.
            final byte[] data = new byte[1];
            random.nextBytes(data);
            final ServiceToken serviceToken = new ServiceToken(p2pCtx, SERVICE_TOKEN_NAME, data, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext());
            builder.addPeerServiceToken(serviceToken);
            
            // Delete the service token.
            builder.deletePeerServiceToken(serviceToken);
            final MessageHeader messageHeader = builder.getHeader();
            final Set<ServiceToken> tokens = messageHeader.getPeerServiceTokens();
            for (final ServiceToken token : tokens) {
                if (token.getName().equals(SERVICE_TOKEN_NAME)) {
                    assertEquals(0, token.getData().length);
                    return;
                }
            }
            fail("Deleted peer service token not found.");
        }
        
        @Test
        public void deleteUnknownPeerServiceToken() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            builder.deletePeerServiceToken(SERVICE_TOKEN_NAME, true, true);
            final MessageHeader messageHeader = builder.getHeader();
            final Set<ServiceToken> tokens = messageHeader.getPeerServiceTokens();
            for (final ServiceToken token : tokens) {
                if (token.getName().equals(SERVICE_TOKEN_NAME)) {
                    assertEquals(0, token.getData().length);
                    return;
                }
            }
            fail("Deleted unknown peer service token not found.");
        }
        
        @Test
        public void setMasterToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MslStore store = trustedNetCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, null, null);
            builder.setAuthTokens(MASTER_TOKEN, null);
            
            // The message service tokens will include all unbound service
            // tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }
            
            assertEquals(updatedServiceTokens, builder.getServiceTokens());
            assertTrue(builder.getPeerServiceTokens().isEmpty());
            final MessageHeader messageHeader = builder.getHeader();
            assertEquals(updatedServiceTokens, messageHeader.getServiceTokens());
            assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        }
        
        @Test
        public void setExistingMasterToken() throws MslException {
            final MslStore store = trustedNetCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(USER_ID, USER_ID_TOKEN);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null);
            builder.setAuthTokens(MASTER_TOKEN, null);
            
            // The message service tokens will include all unbound service
            // tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }

            assertEquals(updatedServiceTokens, builder.getServiceTokens());
            assertTrue(builder.getPeerServiceTokens().isEmpty());
            final MessageHeader messageHeader = builder.getHeader();
            assertEquals(updatedServiceTokens, messageHeader.getServiceTokens());
            assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        }
        
        @Test
        public void setAuthTokens() throws MslEncodingException, MslCryptoException, MslException {
            final MslStore store = trustedNetCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(USER_ID, USER_ID_TOKEN);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, null, null);
            builder.setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);
            
            // The message service tokens will include all unbound service
            // tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }

            assertEquals(updatedServiceTokens, builder.getServiceTokens());
            assertTrue(builder.getPeerServiceTokens().isEmpty());
            final MessageHeader messageHeader = builder.getHeader();
            assertEquals(updatedServiceTokens, messageHeader.getServiceTokens());
            assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        }
        
        @Test
        public void setExistingAuthTokens() throws MslEncodingException, MslCryptoException, MslException {
            final MslStore store = trustedNetCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(USER_ID, USER_ID_TOKEN);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null);
            builder.setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);
            
            // The message service tokens will include all unbound service
            // tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }

            assertEquals(updatedServiceTokens, builder.getServiceTokens());
            assertTrue(builder.getPeerServiceTokens().isEmpty());
            final MessageHeader messageHeader = builder.getHeader();
            assertEquals(updatedServiceTokens, messageHeader.getServiceTokens());
            assertTrue(messageHeader.getPeerServiceTokens().isEmpty());
        }
        
        @Test
        public void setNullMasterToken() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, null, null);
            builder.setAuthTokens(null, null);
            final MessageHeader header = builder.getHeader();
            assertNotNull(header);
            
            assertNull(header.getMasterToken());
            assertNull(header.getUserIdToken());
        }
        
        @Test(expected = MslInternalException.class)
        public void setMismatchedAuthTokens() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, null, null);
            builder.setAuthTokens(MASTER_TOKEN, PEER_USER_ID_TOKEN);
        }
        
        @Test
        public void setUser() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null);
            builder.setUser(USER_ID_TOKEN.getUser());
            final UserIdToken userIdToken = builder.getUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(USER_ID_TOKEN.getUser(), userIdToken.getUser());
        }
        
        @Test(expected = MslInternalException.class)
        public void setUserNoMasterToken() throws MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, null, null);
            builder.setUser(USER_ID_TOKEN.getUser());
        }
        
        @Test(expected = MslInternalException.class)
        public void setUserHasUserIdToken() throws MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            builder.setUser(USER_ID_TOKEN.getUser());
        }
        
        @Test
        public void setPeerUser() throws MslMessageException, MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, null, null);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
            builder.setUser(PEER_USER_ID_TOKEN.getUser());
            final UserIdToken userIdToken = builder.getPeerUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(PEER_USER_ID_TOKEN.getUser(), userIdToken.getUser());
        }
        
        @Test(expected = MslInternalException.class)
        public void setPeerUserNoPeerMasterToken() throws MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, null, null);
            builder.setUser(PEER_USER_ID_TOKEN.getUser());
        }
        
        @Test(expected = MslInternalException.class)
        public void setPeerUserHasPeerUserIdToken() throws MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder builder = messageFactory.createRequest(p2pCtx, null, null);
            builder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            builder.setUser(USER_ID_TOKEN.getUser());
        }
        
        @Test(expected = MslInternalException.class)
        public void negativeMessageId() throws MslException {
            messageFactory.createRequest(trustedNetCtx, null, null, -1);
        }
        
        @Test(expected = MslInternalException.class)
        public void tooLargeMessageId() throws MslException {
            messageFactory.createRequest(trustedNetCtx, null, null, MslConstants.MAX_LONG_VALUE + 1);
        }
    }
    
    /** Create error unit tests. */
        public static class CreateErrorTest {
        private static final Long REQUEST_MESSAGE_ID = Long.valueOf(17L);
        private static final MslError MSL_ERROR = MslError.MSL_PARSE_ERROR;
        private static final String USER_MESSAGE = "user message";
        
        @Test
        public void ctor() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
            final ErrorHeader errorHeader = messageFactory.createErrorResponse(trustedNetCtx, REQUEST_MESSAGE_ID, MSL_ERROR, USER_MESSAGE);
            assertNotNull(errorHeader);
            assertEquals(MSL_ERROR.getResponseCode(), errorHeader.getErrorCode());
            assertEquals(MSL_ERROR.getMessage(), errorHeader.getErrorMessage());
            assertEquals(USER_MESSAGE, errorHeader.getUserMessage());
            assertEquals(REQUEST_MESSAGE_ID + 1, errorHeader.getMessageId());
        }
        
        @Test
        public void nullRecipient() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
            final ErrorHeader errorHeader = messageFactory.createErrorResponse(trustedNetCtx, REQUEST_MESSAGE_ID, MSL_ERROR, USER_MESSAGE);
            assertNotNull(errorHeader);
            assertEquals(MSL_ERROR.getResponseCode(), errorHeader.getErrorCode());
            assertEquals(MSL_ERROR.getMessage(), errorHeader.getErrorMessage());
            assertEquals(USER_MESSAGE, errorHeader.getUserMessage());
            assertEquals(REQUEST_MESSAGE_ID + 1, errorHeader.getMessageId());
        }
        
        @Test
        public void maxMessageId() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
            final Long messageId = MslConstants.MAX_LONG_VALUE;
            final ErrorHeader errorHeader = messageFactory.createErrorResponse(trustedNetCtx, messageId, MSL_ERROR, USER_MESSAGE);
            assertNotNull(errorHeader);
            assertEquals(MSL_ERROR.getResponseCode(), errorHeader.getErrorCode());
            assertEquals(MSL_ERROR.getMessage(), errorHeader.getErrorMessage());
            assertEquals(USER_MESSAGE, errorHeader.getUserMessage());
            assertEquals(0, errorHeader.getMessageId());
        }
        
        @Test
        public void nullMessageId() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
            final ErrorHeader errorHeader = messageFactory.createErrorResponse(trustedNetCtx, null, MSL_ERROR, USER_MESSAGE);
            assertNotNull(errorHeader);
            assertEquals(MSL_ERROR.getResponseCode(), errorHeader.getErrorCode());
            assertEquals(MSL_ERROR.getMessage(), errorHeader.getErrorMessage());
            assertEquals(USER_MESSAGE, errorHeader.getUserMessage());
            assertTrue(errorHeader.getMessageId() > 0);
        }
        
        @Test(expected = MslInternalException.class)
        public void negativeMessageId() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
            final Long messageId = -12L;
            messageFactory.createErrorResponse(trustedNetCtx, messageId, MSL_ERROR, USER_MESSAGE);
        }
        
        @Test
        public void nullUserMessage() throws MslEncodingException, MslEntityAuthException, MslMessageException, MslCryptoException {
            final ErrorHeader errorHeader = messageFactory.createErrorResponse(trustedNetCtx, REQUEST_MESSAGE_ID, MSL_ERROR, null);
            assertNotNull(errorHeader);
            assertEquals(MSL_ERROR.getResponseCode(), errorHeader.getErrorCode());
            assertEquals(MSL_ERROR.getMessage(), errorHeader.getErrorMessage());
            assertNull(errorHeader.getUserMessage());
            assertEquals(REQUEST_MESSAGE_ID + 1, errorHeader.getMessageId());
        }
    }
    
    /** Create response unit tests. */
    public static class CreateResponseTest {
        private static final long REQUEST_MESSAGE_ID = 17L;
        
        private static final String KEY_PAIR_ID = "rsaKeyPairId";
        private static PublicKey RSA_PUBLIC_KEY;
        private static PrivateKey RSA_PRIVATE_KEY;
        private static final Map<String,ICryptoContext> CRYPTO_CONTEXTS = new HashMap<String,ICryptoContext>();
        
        private static MslObject ISSUER_DATA;
        private static MslUser USER;
        
        /**
         * @param value the value to increment.
         * @return the value + 1, wrapped back to zero on overflow.
         */
        private static long incrementLong(final long value) {
            if (value == MslConstants.MAX_LONG_VALUE) return 0;
            return value + 1;
        }
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @BeforeClass
        public static void setup() throws NoSuchAlgorithmException, MslEncoderException {
            final KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
            final KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
            RSA_PUBLIC_KEY = rsaKeyPair.getPublic();
            RSA_PRIVATE_KEY = rsaKeyPair.getPrivate();
            ISSUER_DATA = encoder.parseObject("{ 'issuerid' : 17 }".getBytes());
            USER = MockEmailPasswordAuthenticationFactory.USER;
        }
        
        @AfterClass
        public static void teardown() {
            USER = null;
            RSA_PRIVATE_KEY = null;
            RSA_PUBLIC_KEY = null;
        }
        
        @Before
        public void reset() {
            trustedNetCtx.getMslStore().clearCryptoContexts();
            trustedNetCtx.getMslStore().clearServiceTokens();
            p2pCtx.getMslStore().clearCryptoContexts();
            p2pCtx.getMslStore().clearServiceTokens();
        }
        
        @Test
        public void createNullResponse() throws MslEncodingException, MslCryptoException, MslMessageException, MslMasterTokenException, MslEntityAuthException, MslException {
            // This will not exercise any of the complex logic, so no key
            // request data, entity auth data, or user auth data. Just tokens.
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            for (final ServiceToken serviceToken : serviceTokens)
                requestBuilder.addServiceToken(serviceToken);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            assertTrue(responseBuilder.willEncryptHeader());
            assertTrue(responseBuilder.willEncryptPayloads());
            assertEquals(serviceTokens, responseBuilder.getServiceTokens());
            assertTrue(responseBuilder.getPeerServiceTokens().isEmpty());
            
            final MessageHeader response = responseBuilder.getHeader();
            assertNotNull(response);
            assertNull(response.getNonReplayableId());
            assertFalse(response.isRenewable());
            assertFalse(response.isHandshake());
            assertNotNull(response.getCryptoContext());
            assertNull(response.getEntityAuthenticationData());
            assertTrue(response.getKeyRequestData().isEmpty());
            assertNull(response.getKeyResponseData());
            assertEquals(MASTER_TOKEN, response.getMasterToken());
            assertEquals(incrementLong(request.getMessageId()), response.getMessageId());
            assertEquals(trustedNetCtx.getMessageCapabilities(), response.getMessageCapabilities());
            assertNull(response.getPeerMasterToken());
            assertTrue(response.getPeerServiceTokens().isEmpty());
            assertNull(response.getPeerUserIdToken());
            assertTrue(response.getServiceTokens().equals(serviceTokens));
            assertNull(response.getUserAuthenticationData());
            assertEquals(USER_ID_TOKEN, response.getUserIdToken());
        }
        
        @Test
        public void createNullPeerResponse() throws MslEncodingException, MslCryptoException, MslMessageException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            // This will not exercise any of the complex logic, so no key
            // request data, entity auth data, or user auth data. Just tokens.
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            requestBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            for (final ServiceToken serviceToken : serviceTokens)
                requestBuilder.addServiceToken(serviceToken);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            for (final ServiceToken peerServiceToken : peerServiceTokens)
                requestBuilder.addPeerServiceToken(peerServiceToken);
            final MessageHeader request = requestBuilder.getHeader();
            
            // The tokens should be swapped.
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            assertTrue(responseBuilder.willEncryptHeader());
            assertTrue(responseBuilder.willEncryptPayloads());
            assertEquals(serviceTokens, responseBuilder.getPeerServiceTokens());
            assertEquals(peerServiceTokens, responseBuilder.getServiceTokens());
            final MessageHeader response = responseBuilder.getHeader();
            assertNotNull(response);
            assertNull(response.getNonReplayableId());
            assertFalse(response.isRenewable());
            assertFalse(response.isHandshake());
            assertNotNull(response.getCryptoContext());
            assertNull(response.getEntityAuthenticationData());
            assertTrue(response.getKeyRequestData().isEmpty());
            assertNull(response.getKeyResponseData());
            assertEquals(PEER_MASTER_TOKEN, response.getMasterToken());
            assertEquals(incrementLong(request.getMessageId()), response.getMessageId());
            assertEquals(p2pCtx.getMessageCapabilities(), response.getMessageCapabilities());
            assertEquals(MASTER_TOKEN, response.getPeerMasterToken());
            assertEquals(USER_ID_TOKEN, response.getPeerUserIdToken());
            assertNull(response.getUserAuthenticationData());
            assertEquals(PEER_USER_ID_TOKEN, response.getUserIdToken());
            assertTrue(response.getPeerServiceTokens().equals(serviceTokens));
            assertTrue(response.getServiceTokens().equals(peerServiceTokens));
        }
        
        @Test
        public void createEntityAuthResponse() throws MslEncodingException, MslCryptoException, MslMessageException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, null, null);
            for (final ServiceToken serviceToken : serviceTokens)
                requestBuilder.addServiceToken(serviceToken);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            assertTrue(responseBuilder.willEncryptHeader());
            assertTrue(responseBuilder.willEncryptPayloads());
            assertEquals(serviceTokens, responseBuilder.getServiceTokens());
            assertTrue(responseBuilder.getPeerServiceTokens().isEmpty());
            
            final MessageHeader response = responseBuilder.getHeader();
            assertNotNull(response);
            assertNull(response.getNonReplayableId());
            assertFalse(response.isRenewable());
            assertFalse(response.isHandshake());
            assertNotNull(response.getCryptoContext());
            final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
            assertEquals(entityAuthData, response.getEntityAuthenticationData());
            assertTrue(response.getKeyRequestData().isEmpty());
            assertNull(response.getKeyResponseData());
            assertNull(response.getMasterToken());
            assertEquals(incrementLong(request.getMessageId()), response.getMessageId());
            assertEquals(trustedNetCtx.getMessageCapabilities(), response.getMessageCapabilities());
            assertNull(response.getPeerMasterToken());
            assertTrue(response.getPeerServiceTokens().isEmpty());
            assertNull(response.getPeerUserIdToken());
            assertTrue(response.getServiceTokens().equals(serviceTokens));
            assertNull(response.getUserAuthenticationData());
            assertNull(response.getUserIdToken());
        }
        
        @Test
        public void createEntityAuthPeerResponse() throws MslEncodingException, MslCryptoException, MslMessageException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, null, null);
            requestBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, null, null);
            for (final ServiceToken serviceToken : serviceTokens)
                requestBuilder.addServiceToken(serviceToken);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            for (final ServiceToken peerServiceToken : peerServiceTokens)
                requestBuilder.addPeerServiceToken(peerServiceToken);
            final MessageHeader request = requestBuilder.getHeader();
            
            // The tokens should be swapped.
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            assertTrue(responseBuilder.willEncryptHeader());
            assertTrue(responseBuilder.willEncryptPayloads());
            assertEquals(serviceTokens, responseBuilder.getPeerServiceTokens());
            assertEquals(peerServiceTokens, responseBuilder.getServiceTokens());
            final MessageHeader response = responseBuilder.getHeader();
            assertNotNull(response);
            assertNull(response.getNonReplayableId());
            assertFalse(response.isRenewable());
            assertFalse(response.isHandshake());
            assertNotNull(response.getCryptoContext());
            assertNull(response.getEntityAuthenticationData());
            assertTrue(response.getKeyRequestData().isEmpty());
            assertNull(response.getKeyResponseData());
            assertEquals(PEER_MASTER_TOKEN, response.getMasterToken());
            assertEquals(incrementLong(request.getMessageId()), response.getMessageId());
            assertEquals(p2pCtx.getMessageCapabilities(), response.getMessageCapabilities());
            assertNull(response.getPeerMasterToken());
            assertNull(response.getPeerUserIdToken());
            assertNull(response.getUserAuthenticationData());
            assertEquals(PEER_USER_ID_TOKEN, response.getUserIdToken());
            assertTrue(response.getPeerServiceTokens().equals(serviceTokens));
            assertTrue(response.getServiceTokens().equals(peerServiceTokens));
        }
        
        @Test
        public void createResponse() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setNonReplayable(true);
            responseBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                responseBuilder.addKeyRequestData(keyRequestData);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, null, null);
            for (final ServiceToken serviceToken : serviceTokens)
                responseBuilder.addServiceToken(serviceToken);
            responseBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            assertTrue(responseBuilder.willEncryptHeader());
            assertTrue(responseBuilder.willEncryptPayloads());
            assertEquals(serviceTokens, responseBuilder.getServiceTokens());
            assertTrue(responseBuilder.getPeerServiceTokens().isEmpty());
            final MessageHeader response = responseBuilder.getHeader();
            assertNotNull(response);
            assertNotNull(response.getNonReplayableId());
            assertTrue(response.isRenewable());
            assertFalse(response.isHandshake());
            assertNotNull(response.getCryptoContext());
            assertNull(response.getEntityAuthenticationData());
            assertTrue(response.getKeyRequestData().equals(KEY_REQUEST_DATA));
            assertNull(response.getKeyResponseData());
            assertEquals(MASTER_TOKEN, response.getMasterToken());
            assertEquals(incrementLong(request.getMessageId()), response.getMessageId());
            assertEquals(trustedNetCtx.getMessageCapabilities(), response.getMessageCapabilities());
            assertNull(response.getPeerMasterToken());
            assertTrue(response.getPeerServiceTokens().isEmpty());
            assertNull(response.getPeerUserIdToken());
            assertTrue(response.getServiceTokens().equals(serviceTokens));
            assertEquals(USER_AUTH_DATA, response.getUserAuthenticationData());
            assertEquals(USER_ID_TOKEN, response.getUserIdToken());
        }
        
        @Test
        public void createPeerResponse() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslMessageException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, null, null);
            for (final ServiceToken serviceToken : serviceTokens)
                responseBuilder.addServiceToken(serviceToken);
            responseBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            for (final ServiceToken peerServiceToken : peerServiceTokens)
                responseBuilder.addPeerServiceToken(peerServiceToken);
            assertTrue(responseBuilder.willEncryptHeader());
            assertTrue(responseBuilder.willEncryptPayloads());
            assertEquals(peerServiceTokens, responseBuilder.getPeerServiceTokens());
            assertEquals(serviceTokens, responseBuilder.getServiceTokens());
            final MessageHeader response = responseBuilder.getHeader();
            assertNotNull(response);
            assertNull(response.getNonReplayableId());
            assertFalse(response.isRenewable());
            assertFalse(response.isHandshake());
            assertNotNull(response.getCryptoContext());
            assertEquals(trustedNetCtx.getEntityAuthenticationData(null), response.getEntityAuthenticationData());
            assertTrue(response.getKeyRequestData().isEmpty());
            assertNull(response.getKeyResponseData());
            assertNull(response.getMasterToken());
            assertEquals(incrementLong(request.getMessageId()), response.getMessageId());
            assertEquals(p2pCtx.getMessageCapabilities(), response.getMessageCapabilities());
            assertEquals(PEER_MASTER_TOKEN, response.getPeerMasterToken());
            assertEquals(PEER_USER_ID_TOKEN, response.getPeerUserIdToken());
            assertEquals(USER_AUTH_DATA, response.getUserAuthenticationData());
            assertTrue(response.getPeerServiceTokens().equals(peerServiceTokens));
            assertTrue(response.getServiceTokens().equals(serviceTokens));
            assertNull(response.getUserIdToken());
        }
        
        @Test
        public void createHandshakeResponse() throws MslEncodingException, MslCryptoException, MslMessageException, MslMasterTokenException, MslEntityAuthException, MslException {
            // This will not exercise any of the complex logic, so no key
            // request data, entity auth data, or user auth data. Just tokens.
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            for (final ServiceToken serviceToken : serviceTokens)
                requestBuilder.addServiceToken(serviceToken);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setNonReplayable(true);
            responseBuilder.setRenewable(false);
            responseBuilder.setHandshake(true);
            assertTrue(responseBuilder.willEncryptHeader());
            assertTrue(responseBuilder.willEncryptPayloads());
            assertEquals(serviceTokens, responseBuilder.getServiceTokens());
            assertTrue(responseBuilder.getPeerServiceTokens().isEmpty());
            
            final MessageHeader response = responseBuilder.getHeader();
            assertNotNull(response);
            assertNull(response.getNonReplayableId());
            assertTrue(response.isRenewable());
            assertTrue(response.isHandshake());
            assertNotNull(response.getCryptoContext());
            assertNull(response.getEntityAuthenticationData());
            assertTrue(response.getKeyRequestData().isEmpty());
            assertNull(response.getKeyResponseData());
            assertEquals(MASTER_TOKEN, response.getMasterToken());
            assertEquals(incrementLong(request.getMessageId()), response.getMessageId());
            assertEquals(trustedNetCtx.getMessageCapabilities(), response.getMessageCapabilities());
            assertNull(response.getPeerMasterToken());
            assertTrue(response.getPeerServiceTokens().isEmpty());
            assertNull(response.getPeerUserIdToken());
            assertTrue(response.getServiceTokens().equals(serviceTokens));
            assertNull(response.getUserAuthenticationData());
            assertEquals(USER_ID_TOKEN, response.getUserIdToken());
        }
        
        @Test
        public void createPeerHandshakeResponse() throws MslEncodingException, MslCryptoException, MslMessageException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            // This will not exercise any of the complex logic, so no key
            // request data, entity auth data, or user auth data. Just tokens.
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            requestBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            for (final ServiceToken serviceToken : serviceTokens)
                requestBuilder.addServiceToken(serviceToken);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            for (final ServiceToken peerServiceToken : peerServiceTokens)
                requestBuilder.addPeerServiceToken(peerServiceToken);
            final MessageHeader request = requestBuilder.getHeader();
            
            // The tokens should be swapped.
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            responseBuilder.setNonReplayable(true);
            responseBuilder.setRenewable(false);
            responseBuilder.setHandshake(true);
            assertTrue(responseBuilder.willEncryptHeader());
            assertTrue(responseBuilder.willEncryptPayloads());
            assertEquals(serviceTokens, responseBuilder.getPeerServiceTokens());
            assertEquals(peerServiceTokens, responseBuilder.getServiceTokens());
            
            final MessageHeader response = responseBuilder.getHeader();
            assertNotNull(response);
            assertNull(response.getNonReplayableId());
            assertTrue(response.isRenewable());
            assertTrue(response.isHandshake());
            assertNotNull(response.getCryptoContext());
            assertNull(response.getEntityAuthenticationData());
            assertTrue(response.getKeyRequestData().isEmpty());
            assertNull(response.getKeyResponseData());
            assertEquals(PEER_MASTER_TOKEN, response.getMasterToken());
            assertEquals(incrementLong(request.getMessageId()), response.getMessageId());
            assertEquals(p2pCtx.getMessageCapabilities(), response.getMessageCapabilities());
            assertEquals(MASTER_TOKEN, response.getPeerMasterToken());
            assertEquals(USER_ID_TOKEN, response.getPeerUserIdToken());
            assertNull(response.getUserAuthenticationData());
            assertEquals(PEER_USER_ID_TOKEN, response.getUserIdToken());
            assertTrue(response.getPeerServiceTokens().equals(serviceTokens));
            assertTrue(response.getServiceTokens().equals(peerServiceTokens));
        }

        @Test
        public void willEncryptX509EntityAuth() throws MslException {
            final MslContext x509Ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
            final MessageBuilder requestBuilder = messageFactory.createRequest(x509Ctx, null, null);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(x509Ctx, request);
            assertFalse(responseBuilder.willEncryptHeader());
            assertFalse(responseBuilder.willEncryptPayloads());
        }

        @Test
        public void willEncryptX509EntityAuthKeyExchange() throws MslException {
            final MslContext x509Ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
            final MessageBuilder requestBuilder = messageFactory.createRequest(x509Ctx, null, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(x509Ctx, request);
            assertFalse(responseBuilder.willEncryptHeader());
            assertTrue(responseBuilder.willEncryptPayloads());
        }
        
        @Test
        public void storedServiceTokens() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageHeader request = requestBuilder.getHeader();
            assertTrue(request.getServiceTokens().isEmpty());
            
            final MslStore store = trustedNetCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(USER_ID, USER_ID_TOKEN);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            
            // The message will include all unbound service tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }
            
            assertEquals(updatedServiceTokens, responseBuilder.getServiceTokens());
            assertTrue(responseBuilder.getPeerServiceTokens().isEmpty());
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(updatedServiceTokens, response.getServiceTokens());
            assertTrue(response.getPeerServiceTokens().isEmpty());
        }
        
        @Test
        public void storedPeerServiceTokens() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageHeader request = requestBuilder.getHeader();
            assertTrue(request.getServiceTokens().isEmpty());
            assertTrue(request.getPeerServiceTokens().isEmpty());
            
            final MslStore store = p2pCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(USER_ID, USER_ID_TOKEN);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            
            // Update the set of expected peer service tokens with any unbound
            // service tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }
            
            // The service tokens will all be unbound.
            for (final ServiceToken serviceToken : responseBuilder.getServiceTokens()) {
                assertTrue(serviceToken.isUnbound());
                assertTrue(serviceTokens.contains(serviceToken) || peerServiceTokens.contains(serviceToken));
            }
            assertEquals(updatedServiceTokens, responseBuilder.getPeerServiceTokens());
            final MessageHeader response = responseBuilder.getHeader();
            // The service tokens will all be unbound.
            for (final ServiceToken serviceToken : response.getServiceTokens()) {
                assertTrue(serviceToken.isUnbound());
                assertTrue(serviceTokens.contains(serviceToken) || peerServiceTokens.contains(serviceToken));
            }
            assertEquals(updatedServiceTokens, response.getPeerServiceTokens());
        }
        
        @Test
        public void keyxAddServiceToken() throws MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            assertNull(responseBuilder.getMasterToken());
            final UserIdToken userIdToken = responseBuilder.getUserIdToken();
            assertNotNull(userIdToken);
            assertNotNull(responseBuilder.getKeyExchangeData());
            final MasterToken keyxMasterToken = responseBuilder.getKeyExchangeData().keyResponseData.getMasterToken();
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, keyxMasterToken, userIdToken);
            for (final ServiceToken serviceToken : serviceTokens)
                responseBuilder.addServiceToken(serviceToken);
            final MessageHeader response = responseBuilder.getHeader();
            
            assertEquals(serviceTokens, response.getServiceTokens());
        }
        
        @Test
        public void nullKeyxAddServiceToken() throws MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH);

            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            assertNull(responseBuilder.getMasterToken());
            assertNull(responseBuilder.getKeyExchangeData());
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null);
            for (final ServiceToken serviceToken : serviceTokens)
                responseBuilder.addServiceToken(serviceToken);
        }
        
        @Test
        public void keyxAddMismatchedServiceToken() throws MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH);

            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            assertNull(responseBuilder.getMasterToken());
            assertNotNull(responseBuilder.getKeyExchangeData());
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null);
            for (final ServiceToken serviceToken : serviceTokens)
                responseBuilder.addServiceToken(serviceToken);
        }
        
        @Test
        public void peerKeyxAddMismatchedServiceToken() throws MslException {
            thrown.expect(MslMessageException.class);
            thrown.expectMslError(MslError.SERVICETOKEN_MASTERTOKEN_MISMATCH);

            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, null, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            assertNull(responseBuilder.getMasterToken());
            assertNull(responseBuilder.getUserIdToken());
            assertNotNull(responseBuilder.getKeyExchangeData());
            final MasterToken keyxMasterToken = responseBuilder.getKeyExchangeData().keyResponseData.getMasterToken();
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, keyxMasterToken, null);
            for (final ServiceToken serviceToken : serviceTokens)
                responseBuilder.addServiceToken(serviceToken);
        }
        
        @Test
        public void maxRequestMessageId() throws MslKeyExchangeException, MslUserAuthException, MslException {
            final HeaderData headerData = new HeaderData(MslConstants.MAX_LONG_VALUE, null, false, false, null, null, null, null, null, null);
            final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
            final MessageHeader request = new MessageHeader(trustedNetCtx, null, MASTER_TOKEN, headerData, peerData);
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(0, response.getMessageId());
        }
        
        @Test
        public void renewMasterToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expiration = new Date(System.currentTimeMillis() + 10000);
            final MasterToken requestMasterToken = new MasterToken(trustedNetCtx, renewalWindow, expiration, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, requestMasterToken, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(requestMasterToken, response.getMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(requestMasterToken.getIdentity(), keyxMasterToken.getIdentity());
            assertEquals(incrementLong(requestMasterToken.getSequenceNumber()), keyxMasterToken.getSequenceNumber());
            assertEquals(requestMasterToken.getSerialNumber(), keyxMasterToken.getSerialNumber());
        }
        
        @Test
        public void peerRenewMasterToken() throws MslMasterTokenException, MslEntityAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expirationWindow = new Date(System.currentTimeMillis() + 10000);
            final MasterToken requestMasterToken = new MasterToken(p2pCtx, renewalWindow, expirationWindow, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, requestMasterToken, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getMasterToken());
            assertEquals(requestMasterToken, response.getPeerMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(requestMasterToken.getIdentity(), keyxMasterToken.getIdentity());
            assertEquals(incrementLong(requestMasterToken.getSequenceNumber()), keyxMasterToken.getSequenceNumber());
            assertEquals(requestMasterToken.getSerialNumber(), keyxMasterToken.getSerialNumber());
        }
        
        @Test
        public void renewMasterTokenMaxSequenceNumber() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expirationWindow = new Date(System.currentTimeMillis() + 10000);
            final MasterToken requestMasterToken = new MasterToken(trustedNetCtx, renewalWindow, expirationWindow, MslConstants.MAX_LONG_VALUE, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, requestMasterToken, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            final MasterToken responseMasterToken = response.getMasterToken();
            assertEquals(requestMasterToken.getIdentity(), responseMasterToken.getIdentity());
            assertEquals(requestMasterToken.getSequenceNumber(), responseMasterToken.getSequenceNumber());
            assertEquals(requestMasterToken.getSerialNumber(), responseMasterToken.getSerialNumber());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(requestMasterToken.getIdentity(), keyxMasterToken.getIdentity());
            assertEquals(incrementLong(requestMasterToken.getSequenceNumber()), keyxMasterToken.getSequenceNumber());
            assertEquals(requestMasterToken.getSerialNumber(), keyxMasterToken.getSerialNumber());
        }
        
        @Test
        public void renewMasterTokenFutureRenewalWindow() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() + 10000);
            final Date expirationWindow = new Date(System.currentTimeMillis() + 20000);
            final MasterToken requestMasterToken = new MasterToken(trustedNetCtx, renewalWindow, expirationWindow, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, requestMasterToken, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            final MasterToken responseMasterToken = response.getMasterToken();
            assertEquals(requestMasterToken.getIdentity(), responseMasterToken.getIdentity());
            assertEquals(requestMasterToken.getSequenceNumber(), responseMasterToken.getSequenceNumber());
            assertEquals(requestMasterToken.getSerialNumber(), responseMasterToken.getSerialNumber());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNull(keyResponseData);
        }
        
        @Test
        public void expiredMasterToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
            final Date expirationWindow = new Date(System.currentTimeMillis() - 10000);
            final MasterToken requestMasterToken = new MasterToken(trustedNetCtx, renewalWindow, expirationWindow, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, requestMasterToken, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(requestMasterToken, response.getMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(requestMasterToken.getIdentity(), keyxMasterToken.getIdentity());
            assertEquals(incrementLong(requestMasterToken.getSequenceNumber()), keyxMasterToken.getSequenceNumber());
            assertEquals(requestMasterToken.getSerialNumber(), keyxMasterToken.getSerialNumber());
        }
        
        @Test
        public void nonReplayableRequest() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() + 10000);
            final Date expirationWindow = new Date(System.currentTimeMillis() + 20000);
            final MasterToken requestMasterToken = new MasterToken(trustedNetCtx, renewalWindow, expirationWindow, MslConstants.MAX_LONG_VALUE, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, requestMasterToken, null);
            requestBuilder.setNonReplayable(true);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(requestMasterToken, response.getMasterToken());
            assertNull(response.getKeyResponseData());
        }
        
        @Test
        public void unsupportedKeyExchangeRenewMasterToken() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_FACTORY_NOT_FOUND);
            thrown.expectMessageId(REQUEST_MESSAGE_ID);

            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            for (final KeyExchangeScheme scheme : KeyExchangeScheme.values())
                ctx.removeKeyExchangeFactories(scheme);
            
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expirationWindow = new Date(System.currentTimeMillis() + 10000);
            final MasterToken requestMasterToken = new MasterToken(ctx, renewalWindow, expirationWindow, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final HeaderData headerData = new HeaderData(REQUEST_MESSAGE_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
            final MessageHeader request = new MessageHeader(trustedNetCtx, null, requestMasterToken, headerData, peerData);
                        
            messageFactory.createResponse(ctx, request);
        }
        
        @Test
        public void oneSupportedKeyExchangeRenewMasterToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            for (final KeyExchangeScheme scheme : KeyExchangeScheme.values())
                ctx.removeKeyExchangeFactories(scheme);
            ctx.addKeyExchangeFactory(new SymmetricWrappedExchange(new MockAuthenticationUtils()));
            
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expirationWindow = new Date(System.currentTimeMillis() + 10000);
            final MasterToken requestMasterToken = new MasterToken(ctx, renewalWindow, expirationWindow, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, requestMasterToken, null);
            requestBuilder.setRenewable(true);
            // This should place the supported key exchange scheme in the
            // middle, guaranteeing that we will have to skip one unsupported
            // scheme.
            requestBuilder.addKeyRequestData(new AsymmetricWrappedExchange.RequestData(KEY_PAIR_ID, Mechanism.RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY));
            requestBuilder.addKeyRequestData(new SymmetricWrappedExchange.RequestData(KeyId.PSK));
            requestBuilder.addKeyRequestData(new AsymmetricWrappedExchange.RequestData(KEY_PAIR_ID, Mechanism.RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY));
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(ctx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(requestMasterToken, response.getMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(requestMasterToken.getIdentity(), keyxMasterToken.getIdentity());
            assertEquals(incrementLong(requestMasterToken.getSequenceNumber()), keyxMasterToken.getSequenceNumber());
            assertEquals(requestMasterToken.getSerialNumber(), keyxMasterToken.getSerialNumber());
        }
        
        @Test(expected = MslMasterTokenException.class)
        public void untrustedMasterTokenRenewMasterToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslEncoderException, MslException {
            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expirationWindow = new Date(System.currentTimeMillis() + 10000);
            final MasterToken requestMasterToken = new MasterToken(ctx, renewalWindow, expirationWindow, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final HeaderData headerData = new HeaderData(REQUEST_MESSAGE_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
            final MessageHeader request = new MessageHeader(ctx, null, requestMasterToken, headerData, peerData);
            
            // Encode the request. This will use the MSL crypto context to
            // encrypt and sign the master token.
            final MslObject mo = MslTestUtils.toMslObject(encoder, request);

            // The master token's crypto context must be cached, so we can
            // rebuild the message.
            final ICryptoContext cryptoContext = new SessionCryptoContext(ctx, requestMasterToken);
            ctx.getMslStore().setCryptoContext(requestMasterToken, cryptoContext);

            // Change the MSL crypto context so the master token can no longer be
            // verified or decrypted.
            final byte[] mke = new byte[16];
            final byte[] mkh = new byte[32];
            final byte[] mkw = new byte[16];
            random.nextBytes(mke);
            random.nextBytes(mkh);
            random.nextBytes(mkw);
            final SecretKey encryptionKey = new SecretKeySpec(mke, JcaAlgorithm.AES);
            final SecretKey hmacKey = new SecretKeySpec(mkh, JcaAlgorithm.HMAC_SHA256);
            final SecretKey wrappingKey = new SecretKeySpec(mkw, JcaAlgorithm.AESKW);
            ctx.setMslCryptoContext(new SymmetricCryptoContext(ctx, "clientMslCryptoContext", encryptionKey, hmacKey, wrappingKey));

            // Reconstruct the request now that we no longer have the same
            // MSL crypto context.
            final MessageHeader untrustedRequest = (MessageHeader)Header.parseHeader(ctx, mo, CRYPTO_CONTEXTS);

            messageFactory.createResponse(ctx, untrustedRequest);
        }
        
        @Test
        public void keyResponseData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder localRequestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            localRequestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                localRequestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader localRequest = localRequestBuilder.getHeader();
            
            final MessageBuilder remoteResponseBuilder = messageFactory.createResponse(trustedNetCtx, localRequest);
            final MessageHeader remoteResponse = remoteResponseBuilder.getHeader();
            final KeyResponseData keyResponseData = remoteResponse.getKeyResponseData();
            assertNotNull(keyResponseData);
            
            final MessageBuilder localResponseBuilder = messageFactory.createResponse(trustedNetCtx, remoteResponse);
            final MessageHeader localResponse = localResponseBuilder.getHeader();
            final MasterToken localMasterToken = localResponse.getMasterToken();
            assertNotNull(localMasterToken);
            assertEquals(keyResponseData.getMasterToken(), localMasterToken);
        }
        
        @Test
        public void peerKeyResponseData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder localRequestBuilder = messageFactory.createRequest(p2pCtx, null, null);
            localRequestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                localRequestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader localRequest = localRequestBuilder.getHeader();
            
            final MessageBuilder remoteResponseBuilder = messageFactory.createResponse(p2pCtx, localRequest);
            final MessageHeader remoteResponse = remoteResponseBuilder.getHeader();
            assertNull(remoteResponse.getMasterToken());
            assertNull(remoteResponse.getPeerMasterToken());
            final KeyResponseData keyResponseData = remoteResponse.getKeyResponseData();
            assertNotNull(keyResponseData);
            
            final MessageBuilder localResponseBuilder = messageFactory.createResponse(p2pCtx, remoteResponse);
            final MessageHeader localResponse = localResponseBuilder.getHeader();
            final MasterToken localMasterToken = localResponse.getMasterToken();
            assertNotNull(localMasterToken);
            assertEquals(keyResponseData.getMasterToken(), localMasterToken);
            assertNull(localResponse.getPeerMasterToken());
            
            final MessageBuilder remoteSecondResponseBuilder = messageFactory.createResponse(p2pCtx, localResponse);
            final MessageHeader remoteSecondResponse = remoteSecondResponseBuilder.getHeader();
            assertNull(remoteResponse.getMasterToken());
            final MasterToken remotePeerMasterToken = remoteSecondResponse.getPeerMasterToken();
            assertNotNull(remotePeerMasterToken);
            assertEquals(localMasterToken, remotePeerMasterToken);
        }
        
        @Test
        public void entityAuthDataNotRenewable() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getMasterToken());
            assertEquals(trustedNetCtx.getEntityAuthenticationData(null), response.getEntityAuthenticationData());
            assertEquals(incrementLong(request.getMessageId()), response.getMessageId());
        }
        
        @Test
        public void entityAuthDataRenewable() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(trustedNetCtx.getEntityAuthenticationData(null).getIdentity(), keyxMasterToken.getIdentity());
        }
        
        @Test
        public void peerEntityAuthDataRenewable() throws MslKeyExchangeException, MslMasterTokenException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, null, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getMasterToken());
            assertNull(response.getPeerMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertNotNull(keyxMasterToken);
            assertEquals(p2pCtx.getEntityAuthenticationData(null).getIdentity(), keyxMasterToken.getIdentity());
        }
        
        @Test
        public void unsupportedKeyExchangeEntityAuthData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_FACTORY_NOT_FOUND);
            thrown.expectMessageId(REQUEST_MESSAGE_ID);

            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            for (final KeyExchangeScheme scheme : KeyExchangeScheme.values())
                ctx.removeKeyExchangeFactories(scheme);
            
            final HeaderData headerData = new HeaderData(REQUEST_MESSAGE_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
            final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
            final MessageHeader request = new MessageHeader(ctx, ctx.getEntityAuthenticationData(null), null, headerData, peerData);
            
            messageFactory.createResponse(ctx, request);
        }
        
        @Test
        public void oneSupportedKeyExchangeEntityAuthData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            for (final KeyExchangeScheme scheme : KeyExchangeScheme.values())
                ctx.removeKeyExchangeFactories(scheme);
            ctx.addKeyExchangeFactory(new AsymmetricWrappedExchange(new MockAuthenticationUtils()));
            
            final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, null, null);
            requestBuilder.setRenewable(true);
            // This should place the supported key exchange scheme in the
            // middle, guaranteeing that we will have to skip one unsupported
            // scheme.
            requestBuilder.addKeyRequestData(new SymmetricWrappedExchange.RequestData(KeyId.SESSION));
            requestBuilder.addKeyRequestData(new AsymmetricWrappedExchange.RequestData(KEY_PAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY));
            requestBuilder.addKeyRequestData(new SymmetricWrappedExchange.RequestData(KeyId.PSK));
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(ctx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertNotNull(response.getKeyResponseData());
        }
        
        @Test
        public void renewUserIdToken() throws MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expiration = new Date(System.currentTimeMillis() + 10000);
            final UserIdToken requestUserIdToken = new UserIdToken(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken);
            requestBuilder.setRenewable(true);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(MASTER_TOKEN, response.getMasterToken());
            final UserIdToken responseUserIdToken = response.getUserIdToken();
            assertNotNull(responseUserIdToken);
            assertEquals(requestUserIdToken.getUser(), responseUserIdToken.getUser());
            assertEquals(requestUserIdToken.getMasterTokenSerialNumber(), responseUserIdToken.getMasterTokenSerialNumber());
            assertEquals(requestUserIdToken.getSerialNumber(), responseUserIdToken.getSerialNumber());
            assertFalse(responseUserIdToken.isRenewable(null));
        }
        
        @Test
        public void renewUserIdTokenNotRenewable() throws MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expiration = new Date(System.currentTimeMillis() + 10000);
            final UserIdToken requestUserIdToken = new UserIdToken(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(MASTER_TOKEN, response.getMasterToken());
            final UserIdToken responseUserIdToken = response.getUserIdToken();
            assertNotNull(responseUserIdToken);
            assertEquals(requestUserIdToken.getUser(), responseUserIdToken.getUser());
            assertEquals(requestUserIdToken.getMasterTokenSerialNumber(), responseUserIdToken.getMasterTokenSerialNumber());
            assertEquals(requestUserIdToken.getSerialNumber(), responseUserIdToken.getSerialNumber());
            assertEquals(requestUserIdToken.getRenewalWindow(), responseUserIdToken.getRenewalWindow());
            assertEquals(requestUserIdToken.getExpiration(), responseUserIdToken.getExpiration());
        }
        
        @Test
        public void peerRenewUserIdToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expiration = new Date(System.currentTimeMillis() + 10000);
            final UserIdToken requestUserIdToken = new UserIdToken(p2pCtx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, requestUserIdToken);
            requestBuilder.setRenewable(true);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(MASTER_TOKEN, response.getPeerMasterToken());
            assertNull(response.getUserIdToken());
            final UserIdToken responseUserIdToken = response.getPeerUserIdToken();
            assertNotNull(responseUserIdToken);
            assertEquals(requestUserIdToken.getUser(), responseUserIdToken.getUser());
            assertEquals(requestUserIdToken.getMasterTokenSerialNumber(), responseUserIdToken.getMasterTokenSerialNumber());
            assertEquals(requestUserIdToken.getSerialNumber(), responseUserIdToken.getSerialNumber());
            assertFalse(responseUserIdToken.isRenewable(null));
        }
        
        @Test
        public void expiredUserIdToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
            final Date expiration = new Date(System.currentTimeMillis() - 10000);
            final UserIdToken requestUserIdToken = new UserIdToken(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken);
            requestBuilder.setRenewable(true);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(MASTER_TOKEN, response.getMasterToken());
            final UserIdToken responseUserIdToken = response.getUserIdToken();
            assertNotNull(responseUserIdToken);
            assertEquals(requestUserIdToken.getUser(), responseUserIdToken.getUser());
            assertEquals(requestUserIdToken.getMasterTokenSerialNumber(), responseUserIdToken.getMasterTokenSerialNumber());
            assertEquals(requestUserIdToken.getSerialNumber(), responseUserIdToken.getSerialNumber());
            assertFalse(responseUserIdToken.isExpired(null));
        }
        
        @Test
        public void expiredUserIdTokenNotRenewable() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
            final Date expiration = new Date(System.currentTimeMillis() - 10000);
            final UserIdToken requestUserIdToken = new UserIdToken(trustedNetCtx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, requestUserIdToken);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(MASTER_TOKEN, response.getMasterToken());
            final UserIdToken responseUserIdToken = response.getUserIdToken();
            assertNotNull(responseUserIdToken);
            assertEquals(requestUserIdToken.getUser(), responseUserIdToken.getUser());
            assertEquals(requestUserIdToken.getMasterTokenSerialNumber(), responseUserIdToken.getMasterTokenSerialNumber());
            assertEquals(requestUserIdToken.getSerialNumber(), responseUserIdToken.getSerialNumber());
            assertFalse(responseUserIdToken.isExpired(null));
        }
        
        @Test
        public void expiredUserIdTokenServerMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            
            final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
            final Date expiration = new Date(System.currentTimeMillis() - 10000);
            final UserIdToken requestUserIdToken = new UserIdToken(ctx, renewalWindow, expiration, MASTER_TOKEN, 1L, ISSUER_DATA, USER);

            // Change the MSL crypto context so the master token and user ID
            // token are not issued by the local entity.
            ctx.setMslCryptoContext(ALT_MSL_CRYPTO_CONTEXT);
            
            // Now rebuild the user ID token and the build the request.
            final MslObject userIdTokenMo = MslTestUtils.toMslObject(encoder, requestUserIdToken);
            final UserIdToken unverifiedUserIdToken = new UserIdToken(ctx, userIdTokenMo, MASTER_TOKEN);
            final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, MASTER_TOKEN, unverifiedUserIdToken);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(ctx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(MASTER_TOKEN, response.getMasterToken());
            final UserIdToken responseUserIdToken = response.getUserIdToken();
            assertNotNull(responseUserIdToken);
            // Can't compare users because the unverified user ID token won't
            // have it.
            assertEquals(unverifiedUserIdToken.getMasterTokenSerialNumber(), responseUserIdToken.getMasterTokenSerialNumber());
            assertEquals(unverifiedUserIdToken.getSerialNumber(), responseUserIdToken.getSerialNumber());
            assertFalse(responseUserIdToken.isExpired(null));
        }
        
        @Test
        public void renewMasterTokenAndRenewUserIdToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expiration = new Date(System.currentTimeMillis() + 10000);
            final MasterToken requestMasterToken = new MasterToken(trustedNetCtx, renewalWindow, expiration, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final UserIdToken requestUserIdToken = new UserIdToken(trustedNetCtx, renewalWindow, expiration, requestMasterToken, 1L, ISSUER_DATA, USER);
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, requestMasterToken, requestUserIdToken);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(requestMasterToken, response.getMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(requestMasterToken.getIdentity(), keyxMasterToken.getIdentity());
            assertEquals(incrementLong(requestMasterToken.getSequenceNumber()), keyxMasterToken.getSequenceNumber());
            assertEquals(requestMasterToken.getSerialNumber(), keyxMasterToken.getSerialNumber());
            final UserIdToken responseUserIdToken = response.getUserIdToken();
            assertNotNull(responseUserIdToken);
            assertEquals(requestUserIdToken.getUser(), responseUserIdToken.getUser());
            assertEquals(requestUserIdToken.getMasterTokenSerialNumber(), responseUserIdToken.getMasterTokenSerialNumber());
            assertEquals(requestUserIdToken.getSerialNumber(), responseUserIdToken.getSerialNumber());
        }
        
        @Test
        public void renewTokensNoKeyRequestData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expiration = new Date(System.currentTimeMillis() + 10000);
            final MasterToken requestMasterToken = new MasterToken(trustedNetCtx, renewalWindow, expiration, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final UserIdToken requestUserIdToken = new UserIdToken(trustedNetCtx, renewalWindow, expiration, requestMasterToken, 1L, ISSUER_DATA, USER);
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, requestMasterToken, requestUserIdToken);
            requestBuilder.setRenewable(true);
            final MessageHeader request = requestBuilder.getHeader();

            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            final MasterToken responseMasterToken = response.getMasterToken();
            final UserIdToken responseUserIdToken = response.getUserIdToken();
            assertEquals(requestMasterToken, responseMasterToken);
            assertEquals(requestMasterToken.getRenewalWindow(), responseMasterToken.getRenewalWindow());
            assertEquals(requestMasterToken.getExpiration(), responseMasterToken.getExpiration());
            assertEquals(requestUserIdToken, responseUserIdToken);
            assertFalse(requestUserIdToken.getRenewalWindow().equals(responseUserIdToken.getRenewalWindow()));
            assertFalse(requestUserIdToken.getExpiration().equals(responseUserIdToken.getExpiration()));
            assertNull(response.getKeyResponseData());
        }
        
        @Test
        public void peerRenewMasterTokenAndRenewUserIdToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() - 10000);
            final Date expiration = new Date(System.currentTimeMillis() + 10000);
            final MasterToken requestMasterToken = new MasterToken(p2pCtx, renewalWindow, expiration, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
            final UserIdToken requestUserIdToken = new UserIdToken(p2pCtx, renewalWindow, expiration, requestMasterToken, 1L, ISSUER_DATA, USER);
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, requestMasterToken, requestUserIdToken);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getMasterToken());
            assertEquals(requestMasterToken, response.getPeerMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(requestMasterToken.getIdentity(), keyxMasterToken.getIdentity());
            assertEquals(incrementLong(requestMasterToken.getSequenceNumber()), keyxMasterToken.getSequenceNumber());
            assertEquals(requestMasterToken.getSerialNumber(), keyxMasterToken.getSerialNumber());
            assertNull(response.getUserIdToken());
            final UserIdToken responseUserIdToken = response.getPeerUserIdToken();
            assertNotNull(responseUserIdToken);
            assertEquals(requestUserIdToken.getUser(), responseUserIdToken.getUser());
            assertEquals(requestUserIdToken.getMasterTokenSerialNumber(), responseUserIdToken.getMasterTokenSerialNumber());
            assertEquals(requestUserIdToken.getSerialNumber(), responseUserIdToken.getSerialNumber());
        }
        
        @Test
        public void masterTokenUserAuthData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null);
            requestBuilder.setRenewable(true);
            requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            final UserIdToken userIdToken = response.getUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(MockEmailPasswordAuthenticationFactory.USER, userIdToken.getUser());
        }
        
        @Test
        public void masterTokenUserAuthenticated() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            
            final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, MASTER_TOKEN, null);
            requestBuilder.setRenewable(true);
            requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MslObject requestMo = MslTestUtils.toMslObject(encoder, request);
            final MessageHeader moRequest = (MessageHeader)Header.parseHeader(ctx, requestMo, CRYPTO_CONTEXTS);
            assertNotNull(moRequest.getUser());
            
            // Remove support for user authentication to prove the response
            // does not perform it.
            ctx.removeUserAuthenticationFactory(USER_AUTH_DATA.getScheme());
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(ctx, moRequest);
            final MessageHeader response = responseBuilder.getHeader();
            final UserIdToken userIdToken = response.getUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(MockEmailPasswordAuthenticationFactory.USER, userIdToken.getUser());
        }
        
        @Test
        public void peerMasterTokenUserAuthData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null);
            requestBuilder.setRenewable(true);
            requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getUserIdToken());
            final UserIdToken userIdToken = response.getPeerUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(MockEmailPasswordAuthenticationFactory.USER, userIdToken.getUser());
        }
        
        @Test
        public void peerMasterTokenUserAuthenticated() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, true);
            
            final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, MASTER_TOKEN, null);
            requestBuilder.setRenewable(true);
            requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MslObject requestMo = MslTestUtils.toMslObject(encoder, request);
            final MessageHeader moRequest = (MessageHeader)Header.parseHeader(ctx, requestMo, CRYPTO_CONTEXTS);
            assertNotNull(moRequest.getUser());
            
            // Remove support for user authentication to prove the response
            // does not perform it.
            ctx.removeUserAuthenticationFactory(USER_AUTH_DATA.getScheme());
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(ctx, moRequest);
            final MessageHeader response = responseBuilder.getHeader();
            final UserIdToken userIdToken = response.getPeerUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(MockEmailPasswordAuthenticationFactory.USER, userIdToken.getUser());
        }
        
        @Test
        public void entityAuthDataUserAuthData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            requestBuilder.setRenewable(true);
            requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(trustedNetCtx.getEntityAuthenticationData(null).getIdentity(), keyxMasterToken.getIdentity());
            final UserIdToken userIdToken = response.getUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(MockEmailPasswordAuthenticationFactory.USER, userIdToken.getUser());
            assertTrue(userIdToken.isBoundTo(keyxMasterToken));
        }
        
        @Test
        public void entityAuthDataUserAuthenticatedData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            
            final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, null, null);
            requestBuilder.setRenewable(true);
            requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MslObject requestMo = MslTestUtils.toMslObject(encoder, request);
            final MessageHeader moRequest = (MessageHeader)Header.parseHeader(ctx, requestMo, CRYPTO_CONTEXTS);
            assertNotNull(moRequest.getUser());
            
            // Remove support for user authentication to prove the response
            // does not perform it.
            ctx.removeUserAuthenticationFactory(USER_AUTH_DATA.getScheme());
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(ctx, moRequest);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(trustedNetCtx.getEntityAuthenticationData(null).getIdentity(), keyxMasterToken.getIdentity());
            final UserIdToken userIdToken = response.getUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(MockEmailPasswordAuthenticationFactory.USER, userIdToken.getUser());
            assertTrue(userIdToken.isBoundTo(keyxMasterToken));
        }
        
        @Test
        public void entityUserAuthNoKeyRequestData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            requestBuilder.setRenewable(true);
            requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getMasterToken());
            assertNull(response.getUserIdToken());
            assertNull(response.getKeyResponseData());
            assertEquals(trustedNetCtx.getEntityAuthenticationData(null), response.getEntityAuthenticationData());
        }
        
        @Test
        public void peerEntityAuthDataUserAuthData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, null, null);
            requestBuilder.setRenewable(true);
            requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(p2pCtx.getEntityAuthenticationData(null).getIdentity(), keyxMasterToken.getIdentity());
            assertNull(response.getUserIdToken());
            final UserIdToken userIdToken = response.getPeerUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(MockEmailPasswordAuthenticationFactory.USER, userIdToken.getUser());
        }
        
        @Test
        public void peerEntityAuthDataUserAuthenticatedData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslKeyExchangeException, MslUserAuthException, MslException, MslEncoderException {
            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, true);
            
            final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, null, null);
            requestBuilder.setRenewable(true);
            requestBuilder.setUserAuthenticationData(USER_AUTH_DATA);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MslObject requestMo = MslTestUtils.toMslObject(encoder, request);
            final MessageHeader moRequest = (MessageHeader)Header.parseHeader(ctx, requestMo, CRYPTO_CONTEXTS);
            assertNotNull(moRequest.getUser());
            
            // Remove support for user authentication to prove the response
            // does not perform it.
            ctx.removeUserAuthenticationFactory(USER_AUTH_DATA.getScheme());
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(ctx, moRequest);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getMasterToken());
            final KeyResponseData keyResponseData = response.getKeyResponseData();
            assertNotNull(keyResponseData);
            final MasterToken keyxMasterToken = keyResponseData.getMasterToken();
            assertEquals(p2pCtx.getEntityAuthenticationData(null).getIdentity(), keyxMasterToken.getIdentity());
            assertNull(response.getUserIdToken());
            final UserIdToken userIdToken = response.getPeerUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(MockEmailPasswordAuthenticationFactory.USER, userIdToken.getUser());
        }
        
        @Test
        public void unsupportedUserAuthentication() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            thrown.expect(MslUserAuthException.class);
            thrown.expectMslError(MslError.USERAUTH_FACTORY_NOT_FOUND);
            thrown.expectMessageId(REQUEST_MESSAGE_ID);

            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            for (final UserAuthenticationScheme scheme : UserAuthenticationScheme.values())
                ctx.removeUserAuthenticationFactory(scheme);
            
            final HeaderData headerData = new HeaderData(REQUEST_MESSAGE_ID, null, true, false, null, null, null, USER_AUTH_DATA, null, null);
            final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
            final MessageHeader request = new MessageHeader(ctx, null, MASTER_TOKEN, headerData, peerData);
            
            messageFactory.createResponse(ctx, request);
        }
        
        @Test
        public void setMasterToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MslStore store = trustedNetCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setAuthTokens(MASTER_TOKEN, null);
            final MessageHeader messageHeader = responseBuilder.getHeader();
            
            // The message service tokens will include all unbound service
            // tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }
            
            assertTrue(messageHeader.getServiceTokens().equals(updatedServiceTokens));
        }
        
        @Test
        public void setExistingMasterToken() throws MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MslStore store = trustedNetCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, null);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setAuthTokens(MASTER_TOKEN, null);
            final MessageHeader messageHeader = responseBuilder.getHeader();
            
            // The message service tokens will include all unbound service
            // tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }
            
            assertTrue(messageHeader.getServiceTokens().equals(updatedServiceTokens));
        }
        
        @Test
        public void setAuthTokens() throws MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MslStore store = trustedNetCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);
            final MessageHeader messageHeader = responseBuilder.getHeader();
            
            // The message service tokens will include all unbound service
            // tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }
            
            assertTrue(messageHeader.getServiceTokens().equals(updatedServiceTokens));
        }
        
        @Test
        public void setExistingAuthTokens() throws MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MslStore store = trustedNetCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setAuthTokens(MASTER_TOKEN, USER_ID_TOKEN);
            final MessageHeader messageHeader = responseBuilder.getHeader();
            
            // The message service tokens will include all unbound service
            // tokens.
            final Set<ServiceToken> updatedServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    updatedServiceTokens.add(peerServiceToken);
            }
            
            assertTrue(messageHeader.getServiceTokens().equals(updatedServiceTokens));
        }
        
        @Test
        public void setNullMasterToken() throws MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setAuthTokens(null, null);
            final MessageHeader response = responseBuilder.getHeader();
            
            assertNull(response.getMasterToken());
            assertNull(response.getUserIdToken());
        }
        
        @Test(expected = MslInternalException.class)
        public void setMismatchedAuthTokens() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setAuthTokens(MASTER_TOKEN, PEER_USER_ID_TOKEN);
        }
        
        @Test(expected = MslInternalException.class)
        public void setMasterTokenHasKeyExchangeData() throws MslException {
            // The master token must be renewable to force a key exchange to
            // happen.
            final Date renewalWindow = new Date(System.currentTimeMillis() - 1000);
            final Date expiration = new Date(System.currentTimeMillis() + 2000);
            final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
            final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
            final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
            final MasterToken masterToken = new MasterToken(trustedNetCtx, renewalWindow, expiration, 1, 1, null, identity, encryptionKey, hmacKey);
                
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, masterToken, null);
            requestBuilder.setRenewable(true);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setAuthTokens(MASTER_TOKEN, null);
        }
        
        @Test
        public void setMasterTokenHasPeerKeyExchangeData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            for (final KeyRequestData keyRequestData : KEY_REQUEST_DATA)
                requestBuilder.addKeyRequestData(keyRequestData);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MslStore store = p2pCtx.getMslStore();
            store.setCryptoContext(MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(USER_ID, USER_ID_TOKEN);
            store.setCryptoContext(PEER_MASTER_TOKEN, CRYPTO_CONTEXT);
            store.addUserIdToken(PEER_USER_ID, PEER_USER_ID_TOKEN);
            
            final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            store.addServiceTokens(serviceTokens);
            final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(trustedNetCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
            store.addServiceTokens(peerServiceTokens);
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            responseBuilder.setAuthTokens(PEER_MASTER_TOKEN, null);
            final MessageHeader response = responseBuilder.getHeader();
            
            // Build the set of expected service tokens.
            final Set<ServiceToken> expectedServiceTokens = new HashSet<ServiceToken>();
            for (final ServiceToken serviceToken : serviceTokens) {
                if (serviceToken.isUnbound())
                    expectedServiceTokens.add(serviceToken);
            }
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (!peerServiceToken.isUserIdTokenBound())
                    expectedServiceTokens.add(peerServiceToken);
            }
            assertTrue(response.getServiceTokens().equals(expectedServiceTokens));
            
            // Build the set of expected peer service tokens.
            final Set<ServiceToken> expectedPeerServiceTokens = new HashSet<ServiceToken>(serviceTokens);
            for (final ServiceToken peerServiceToken : peerServiceTokens) {
                if (peerServiceToken.isUnbound())
                    expectedPeerServiceTokens.add(peerServiceToken);
            }
            assertTrue(response.getPeerServiceTokens().equals(expectedPeerServiceTokens));
        }
        
        @Test
        public void setUser() throws MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setUser(USER_ID_TOKEN.getUser());
            final UserIdToken userIdToken = responseBuilder.getUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(USER_ID_TOKEN.getUser(), userIdToken.getUser());
        }
        
        @Test(expected = MslInternalException.class)
        public void setUserNoMasterToken() throws MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setUser(USER_ID_TOKEN.getUser());
        }
        
        @Test(expected = MslInternalException.class)
        public void setUserHasUserIdToken() throws MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(trustedNetCtx, request);
            responseBuilder.setUser(USER_ID_TOKEN.getUser());
        }
        
        @Test
        public void setPeerUser() throws MslMessageException, MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            responseBuilder.setUser(USER_ID_TOKEN.getUser());
            final UserIdToken userIdToken = responseBuilder.getPeerUserIdToken();
            assertNotNull(userIdToken);
            assertEquals(USER_ID_TOKEN.getUser(), userIdToken.getUser());
        }
        
        @Test(expected = MslInternalException.class)
        public void setPeerUserNoPeerMasterToken() throws MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, null, null);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            responseBuilder.setUser(USER_ID_TOKEN.getUser());
        }
        
        @Test(expected = MslInternalException.class)
        public void setPeerUserHasPeerUserIdToken() throws MslEncodingException, MslCryptoException, MslException {
            final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
            final MessageHeader request = requestBuilder.getHeader();
            
            final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
            responseBuilder.setUser(USER_ID_TOKEN.getUser());
        }
        
        @Test
        public void oneRequestCapabilities() throws MslException {
            final Set<CompressionAlgorithm> algos = new HashSet<CompressionAlgorithm>();
            algos.add(CompressionAlgorithm.GZIP);
            algos.add(CompressionAlgorithm.LZW);
            final Set<CompressionAlgorithm> gzipOnly = new HashSet<CompressionAlgorithm>();
            gzipOnly.add(CompressionAlgorithm.GZIP);
            
            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            final MessageCapabilities caps = new MessageCapabilities(gzipOnly, null, null);
            ctx.setMessageCapabilities(caps);
            final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, null, null);
            final MessageHeader request = requestBuilder.getHeader();
            assertEquals(caps, request.getMessageCapabilities());
            
            ctx.setMessageCapabilities(new MessageCapabilities(algos, null, null));
            final MessageBuilder responseBuilder = messageFactory.createResponse(ctx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertEquals(caps, response.getMessageCapabilities());
        }
        
        @Test
        public void nullRequestCapabilities() throws MslException {
            final Set<CompressionAlgorithm> algos = new HashSet<CompressionAlgorithm>();
            algos.add(CompressionAlgorithm.GZIP);
            algos.add(CompressionAlgorithm.LZW);
            
            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            ctx.setMessageCapabilities(null);
            final MessageBuilder requestBuilder = messageFactory.createRequest(ctx, null, null);
            final MessageHeader request = requestBuilder.getHeader();
            assertNull(request.getMessageCapabilities());
            
            ctx.setMessageCapabilities(new MessageCapabilities(algos, null, null));
            final MessageBuilder responseBuilder = messageFactory.createResponse(ctx, request);
            final MessageHeader response = responseBuilder.getHeader();
            assertNull(response.getMessageCapabilities());
        }
    }
}
