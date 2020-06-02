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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Random;
import java.util.Set;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMessageException;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.AsymmetricWrappedExchange.RequestData.Mechanism;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Message service token builder unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageServiceTokenBuilderTest {
    private static final String KEY_PAIR_ID = "keyPairId";
    private static final String USER_ID = "userid";
    private static final String TOKEN_NAME = "tokenName";
    private static final String EMPTY_TOKEN_NAME = "";
    private static byte[] DATA;
    private static final boolean ENCRYPT = true;
    private static final CompressionAlgorithm COMPRESSION_ALGO = null;
    
    private static MasterToken MASTER_TOKEN, PEER_MASTER_TOKEN;
    private static UserIdToken USER_ID_TOKEN, PEER_USER_ID_TOKEN;
    private static KeyRequestData KEY_REQUEST_DATA;
    private static MessageFactory messageFactory = new MessageFactory();
    
    private static Random random;
    private static MslContext trustedNetCtx;
    private static MockMessageContext trustedNetMsgCtx;
    private static MslContext p2pCtx;
    private static MockMessageContext p2pMsgCtx;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslKeyExchangeException {
        random = new Random();
        
        trustedNetCtx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        trustedNetMsgCtx = new MockMessageContext(trustedNetCtx, USER_ID, UserAuthenticationScheme.EMAIL_PASSWORD);
        p2pCtx = new MockMslContext(EntityAuthenticationScheme.PSK, true);
        p2pMsgCtx = new MockMessageContext(p2pCtx, USER_ID, UserAuthenticationScheme.EMAIL_PASSWORD);
        
        MASTER_TOKEN = MslTestUtils.getMasterToken(p2pCtx, 1, 1);
        USER_ID_TOKEN = MslTestUtils.getUserIdToken(p2pCtx, MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        
        PEER_MASTER_TOKEN = MslTestUtils.getMasterToken(p2pCtx, 1, 2);
        PEER_USER_ID_TOKEN = MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 1, MockEmailPasswordAuthenticationFactory.USER);
        
        final KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        final KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
        final PrivateKey privateKey = rsaKeyPair.getPrivate();
        final PublicKey publicKey = rsaKeyPair.getPublic();
        KEY_REQUEST_DATA = new AsymmetricWrappedExchange.RequestData(KEY_PAIR_ID, Mechanism.JWEJS_RSA, publicKey, privateKey);
        
        DATA = new byte[128];
        random.nextBytes(DATA);
    }
    
    @AfterClass
    public static void teardown() {
        PEER_USER_ID_TOKEN = null;
        PEER_MASTER_TOKEN = null;
        
        USER_ID_TOKEN = null;
        MASTER_TOKEN = null;
        
        p2pMsgCtx = null;
        p2pCtx = null;
        trustedNetMsgCtx = null;
        trustedNetCtx = null;
        
        random = null;
    }
    
    @After
    public void reset() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslCryptoException, MslKeyExchangeException {
        p2pCtx.getMslStore().clearCryptoContexts();
        p2pCtx.getMslStore().clearServiceTokens();
        p2pCtx.getMslStore().clearUserIdTokens();
        p2pMsgCtx = new MockMessageContext(p2pCtx, USER_ID, UserAuthenticationScheme.EMAIL_PASSWORD);
    }
    
    @Test
    public void primaryMasterToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertTrue(tokenBuilder.isPrimaryMasterTokenAvailable());
        assertFalse(tokenBuilder.isPrimaryUserIdTokenAvailable());
        assertFalse(tokenBuilder.isPeerMasterTokenAvailable());
        assertFalse(tokenBuilder.isPeerUserIdTokenAvailable());
    }
    
    @Test
    public void primaryMasterTokenKeyx() throws MslException {
        final MessageBuilder requestBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
        requestBuilder.setRenewable(true);
        requestBuilder.addKeyRequestData(KEY_REQUEST_DATA);
        final MessageHeader request = requestBuilder.getHeader();
        
        final MessageBuilder responseBuilder =  messageFactory.createResponse(trustedNetCtx, request);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(trustedNetCtx, trustedNetMsgCtx, responseBuilder);
        assertNull(responseBuilder.getMasterToken());
        assertNotNull(responseBuilder.getKeyExchangeData());
        
        assertTrue(tokenBuilder.isPrimaryMasterTokenAvailable());
        assertFalse(tokenBuilder.isPrimaryUserIdTokenAvailable());
        assertFalse(tokenBuilder.isPeerMasterTokenAvailable());
        assertFalse(tokenBuilder.isPeerUserIdTokenAvailable());
    }
    
    @Test
    public void primaryUserIdToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertTrue(tokenBuilder.isPrimaryMasterTokenAvailable());
        assertTrue(tokenBuilder.isPrimaryUserIdTokenAvailable());
        assertFalse(tokenBuilder.isPeerMasterTokenAvailable());
        assertFalse(tokenBuilder.isPeerUserIdTokenAvailable());
    }
    
    @Test
    public void peerMasterToken() throws MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.isPrimaryMasterTokenAvailable());
        assertFalse(tokenBuilder.isPrimaryUserIdTokenAvailable());
        assertTrue(tokenBuilder.isPeerMasterTokenAvailable());
        assertFalse(tokenBuilder.isPeerUserIdTokenAvailable());
    }
    
    @Test
    public void peerMasterTokenKeyx() throws MslException {
        final MessageBuilder requestBuilder = messageFactory.createRequest(p2pCtx, null, null);
        requestBuilder.setRenewable(true);
        requestBuilder.addKeyRequestData(KEY_REQUEST_DATA);
        final MessageHeader request = requestBuilder.getHeader();
        
        final MessageBuilder responseBuilder = messageFactory.createResponse(p2pCtx, request);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, responseBuilder);
        
        assertFalse(tokenBuilder.isPrimaryMasterTokenAvailable());
        assertFalse(tokenBuilder.isPrimaryUserIdTokenAvailable());
        assertFalse(tokenBuilder.isPeerMasterTokenAvailable());
        assertFalse(tokenBuilder.isPeerUserIdTokenAvailable());
    }
    
    @Test
    public void peerUserIdToken() throws MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.isPrimaryMasterTokenAvailable());
        assertFalse(tokenBuilder.isPrimaryUserIdTokenAvailable());
        assertTrue(tokenBuilder.isPeerMasterTokenAvailable());
        assertTrue(tokenBuilder.isPeerUserIdTokenAvailable());
    }
    
    @Test
    public void getPrimaryServiceTokens() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        for (final ServiceToken serviceToken : serviceTokens)
            msgBuilder.addServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertEquals(serviceTokens, tokenBuilder.getPrimaryServiceTokens());
        assertTrue(tokenBuilder.getPeerServiceTokens().isEmpty());
    }
    
    @Test
    public void getPeerServiceTokens() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        for (final ServiceToken peerServiceToken : peerServiceTokens)
            msgBuilder.addPeerServiceToken(peerServiceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertEquals(peerServiceTokens, tokenBuilder.getPeerServiceTokens());
        assertTrue(tokenBuilder.getPrimaryServiceTokens().isEmpty());
    }
    
    @Test
    public void getBothServiceTokens() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final Set<ServiceToken> serviceTokens = MslTestUtils.getServiceTokens(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        for (final ServiceToken serviceToken : serviceTokens)
            msgBuilder.addServiceToken(serviceToken);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final Set<ServiceToken> peerServiceTokens = MslTestUtils.getServiceTokens(p2pCtx, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        for (final ServiceToken peerServiceToken : peerServiceTokens)
            msgBuilder.addPeerServiceToken(peerServiceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);

        assertEquals(serviceTokens, tokenBuilder.getPrimaryServiceTokens());
        assertEquals(peerServiceTokens, tokenBuilder.getPeerServiceTokens());
    }
    
    @Test
    public void addPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertTrue(tokenBuilder.getPrimaryServiceTokens().isEmpty());
        
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPrimaryServiceToken(serviceToken));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(1, serviceTokens.size());
        final ServiceToken builderServiceToken = serviceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(serviceToken, builderServiceToken);
    }
    
    @Test
    public void addNamedPrimaryServiceTokens() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertTrue(tokenBuilder.getPrimaryServiceTokens().isEmpty());
        
        final ServiceToken unboundServiceTokenA = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, null, null, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPrimaryServiceToken(unboundServiceTokenA));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        
        final ServiceToken unboundServiceTokenB = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, null, null, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPrimaryServiceToken(unboundServiceTokenB));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        
        final ServiceToken masterBoundServiceTokenA = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPrimaryServiceToken(masterBoundServiceTokenA));
        assertEquals(2, tokenBuilder.getPrimaryServiceTokens().size());
        
        final ServiceToken masterBoundServiceTokenB = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPrimaryServiceToken(masterBoundServiceTokenB));
        assertEquals(2, tokenBuilder.getPrimaryServiceTokens().size());
        
        final ServiceToken userBoundServiceTokenA = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPrimaryServiceToken(userBoundServiceTokenA));
        assertEquals(3, tokenBuilder.getPrimaryServiceTokens().size());
        
        final ServiceToken userBoundServiceTokenB = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPrimaryServiceToken(userBoundServiceTokenB));
        assertEquals(3, tokenBuilder.getPrimaryServiceTokens().size());
    }
    
    @Test
    public void mismatchedMasterTokenAddPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext());
        assertFalse(tokenBuilder.addPrimaryServiceToken(serviceToken));
        assertTrue(tokenBuilder.getPrimaryServiceTokens().isEmpty());
    }
    
    @Test
    public void mismatchedUserIdTokenAddPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(p2pCtx, MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, userIdToken, false, null, new NullCryptoContext());
        assertFalse(tokenBuilder.addPrimaryServiceToken(serviceToken));
        assertTrue(tokenBuilder.getPrimaryServiceTokens().isEmpty());
    }
    
    @Test
    public void noMasterTokenAddPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, false, null, new NullCryptoContext());
        assertFalse(tokenBuilder.addPrimaryServiceToken(serviceToken));
        assertTrue(tokenBuilder.getPrimaryServiceTokens().isEmpty());
    }
    
    @Test
    public void noUserIdTokenAddPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, false, null, new NullCryptoContext());
        assertFalse(tokenBuilder.addPrimaryServiceToken(serviceToken));
        assertTrue(tokenBuilder.getPrimaryServiceTokens().isEmpty());
    }
    
    @Test
    public void addPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertTrue(tokenBuilder.getPeerServiceTokens().isEmpty());
        
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext());
        tokenBuilder.addPeerServiceToken(serviceToken);
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(1, serviceTokens.size());
        final ServiceToken builderServiceToken = serviceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(serviceToken, builderServiceToken);
    }
    
    @Test
    public void addNamedPeerServiceTokens() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertTrue(tokenBuilder.getPeerServiceTokens().isEmpty());
        
        final ServiceToken unboundServiceTokenA = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, null, null, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPeerServiceToken(unboundServiceTokenA));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        
        final ServiceToken unboundServiceTokenB = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, null, null, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPeerServiceToken(unboundServiceTokenB));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        
        final ServiceToken masterBoundServiceTokenA = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPeerServiceToken(masterBoundServiceTokenA));
        assertEquals(2, tokenBuilder.getPeerServiceTokens().size());
        
        final ServiceToken masterBoundServiceTokenB = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPeerServiceToken(masterBoundServiceTokenB));
        assertEquals(2, tokenBuilder.getPeerServiceTokens().size());
        
        final ServiceToken userBoundServiceTokenA = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPeerServiceToken(userBoundServiceTokenA));
        assertEquals(3, tokenBuilder.getPeerServiceTokens().size());
        
        final ServiceToken userBoundServiceTokenB = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext());
        assertTrue(tokenBuilder.addPeerServiceToken(userBoundServiceTokenB));
        assertEquals(3, tokenBuilder.getPeerServiceTokens().size());
    }
    
    @Test
    public void mismatchedMasterTokenAddPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, false, null, new NullCryptoContext());
        assertFalse(tokenBuilder.addPeerServiceToken(serviceToken));
        assertTrue(tokenBuilder.getPeerServiceTokens().isEmpty());
    }
    
    @Test
    public void mismatchedUserIdTokenAddPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(p2pCtx, PEER_MASTER_TOKEN, 2, MockEmailPasswordAuthenticationFactory.USER);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, userIdToken, false, null, new NullCryptoContext());
        assertFalse(tokenBuilder.addPeerServiceToken(serviceToken));
        assertTrue(tokenBuilder.getPeerServiceTokens().isEmpty());
    }
    
    @Test
    public void noMasterTokenAddPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, false, null, new NullCryptoContext());
        assertFalse(tokenBuilder.addPeerServiceToken(serviceToken));
        assertTrue(tokenBuilder.getPeerServiceTokens().isEmpty());
    }
    
    @Test
    public void noUserIdTokenAddPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, false, null, new NullCryptoContext());
        assertFalse(tokenBuilder.addPeerServiceToken(serviceToken));
        assertTrue(tokenBuilder.getPeerServiceTokens().isEmpty());
    }
    
    @Test(expected = MslInternalException.class)
    public void trustedNetAddPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        final ServiceToken serviceToken = new ServiceToken(trustedNetCtx, TOKEN_NAME, DATA, null, null, false, null, new NullCryptoContext());
        tokenBuilder.addPeerServiceToken(serviceToken);
    }
    
    @Test
    public void addUnboundPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertTrue(tokenBuilder.getPrimaryServiceTokens().isEmpty());
        
        assertTrue(tokenBuilder.addUnboundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(1, serviceTokens.size());
        final ServiceToken serviceToken = serviceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, serviceToken.getName());
        assertArrayEquals(DATA, serviceToken.getData());
        assertEquals(ENCRYPT, serviceToken.isEncrypted());
        assertTrue(serviceToken.isUnbound());
        
        assertEquals(serviceTokens, msgBuilder.getServiceTokens());
    }
    
    @Test
    public void noCryptoContextAddUnboundPrimaryServiceToken() throws MslException {
        p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
        p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);
        
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addUnboundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void addMasterBoundPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertTrue(tokenBuilder.getPrimaryServiceTokens().isEmpty());
        
        assertTrue(tokenBuilder.addMasterBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(1, serviceTokens.size());
        final ServiceToken serviceToken = serviceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, serviceToken.getName());
        assertArrayEquals(DATA, serviceToken.getData());
        assertEquals(ENCRYPT, serviceToken.isEncrypted());
        assertTrue(serviceToken.isBoundTo(MASTER_TOKEN));
        
        assertEquals(serviceTokens, msgBuilder.getServiceTokens());
    }
    
    @Test
    public void noMasterTokenAddMasterBoundPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addMasterBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void noCryptoContextAddMasterBoundPrimaryServiceToken() throws MslEncodingException, MslCryptoException, MslException {
        p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
        p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);
        
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addMasterBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void addUserBoundPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertTrue(tokenBuilder.getPrimaryServiceTokens().isEmpty());
        
        assertTrue(tokenBuilder.addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(1, serviceTokens.size());
        final ServiceToken serviceToken = serviceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, serviceToken.getName());
        assertArrayEquals(DATA, serviceToken.getData());
        assertEquals(ENCRYPT, serviceToken.isEncrypted());
        assertTrue(serviceToken.isBoundTo(USER_ID_TOKEN));
        
        assertEquals(serviceTokens, msgBuilder.getServiceTokens());
    }
    
    @Test
    public void noMasterTokenAddUserBoundPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void noUserIdTokenAddUserBoundPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void noCryptoContextAddUserBoundPrimaryServiceToken() throws MslEncodingException, MslCryptoException, MslException {
        p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
        p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);
        
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addUserBoundPrimaryServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void excludeUnboundPrimaryServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, null, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());

        assertFalse(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, false));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());

        assertFalse(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, true));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, false, false));
        assertEquals(0, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
        
        assertTrue(tokenBuilder.addPrimaryServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePrimaryServiceToken(serviceToken));
        assertEquals(0, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void excludeMasterBoundPrimaryServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, false, false));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());

        assertFalse(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, true));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, false));
        assertEquals(0, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
        
        assertTrue(tokenBuilder.addPrimaryServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePrimaryServiceToken(serviceToken));
        assertEquals(0, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void excludeUserBoundPrimaryServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, false, false));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, false));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, true));
        assertEquals(0, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
        
        assertTrue(tokenBuilder.addPrimaryServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePrimaryServiceToken(serviceToken));
        assertEquals(0, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }

    @Test
    public void excludeUnknownUserBoundPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, false, false));
        assertEquals(0, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, false));
        assertEquals(0, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePrimaryServiceToken(TOKEN_NAME, true, true));
        assertEquals(0, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void deleteUnboundPrimaryServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, null, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());

        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, false));
        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, true));
        assertTrue(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, false, false));
        final Set<ServiceToken> builderServiceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(1, builderServiceTokens.size());
        final ServiceToken builderServiceToken = builderServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, builderServiceToken.getName());
        assertEquals(0, builderServiceToken.getData().length);
        assertFalse(builderServiceToken.isEncrypted());
        assertFalse(builderServiceToken.isMasterTokenBound());
        assertFalse(builderServiceToken.isUserIdTokenBound());
        
        final Set<ServiceToken> msgServiceTokens = msgBuilder.getServiceTokens();
        assertEquals(1, msgServiceTokens.size());
        final ServiceToken msgServiceToken = msgServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, msgServiceToken.getName());
        assertEquals(0, msgServiceToken.getData().length);
        assertFalse(msgServiceToken.isEncrypted());
        assertFalse(msgServiceToken.isMasterTokenBound());
        assertFalse(msgServiceToken.isMasterTokenBound());
        
        assertTrue(tokenBuilder.addPrimaryServiceToken(serviceToken));
        assertTrue(tokenBuilder.deletePrimaryServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void deleteMasterBoundPrimaryServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        
        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, false, false));
        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, true));
        assertTrue(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, false));
        final Set<ServiceToken> builderServiceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(1, builderServiceTokens.size());
        final ServiceToken builderServiceToken = builderServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, builderServiceToken.getName());
        assertEquals(0, builderServiceToken.getData().length);
        assertFalse(builderServiceToken.isEncrypted());
        assertTrue(builderServiceToken.isBoundTo(MASTER_TOKEN));
        assertFalse(builderServiceToken.isUserIdTokenBound());
        
        final Set<ServiceToken> msgServiceTokens = msgBuilder.getServiceTokens();
        assertEquals(1, msgServiceTokens.size());
        final ServiceToken msgServiceToken = msgServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, msgServiceToken.getName());
        assertEquals(0, msgServiceToken.getData().length);
        assertFalse(msgServiceToken.isEncrypted());
        assertTrue(msgServiceToken.isBoundTo(MASTER_TOKEN));
        assertFalse(msgServiceToken.isUserIdTokenBound());
        
        assertTrue(tokenBuilder.addPrimaryServiceToken(serviceToken));
        assertTrue(tokenBuilder.deletePrimaryServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void deleteUserBoundPrimaryServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, MASTER_TOKEN, USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        
        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, false, false));
        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, false));
        assertTrue(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, true));
        final Set<ServiceToken> builderServiceTokens = tokenBuilder.getPrimaryServiceTokens();
        assertEquals(1, builderServiceTokens.size());
        final ServiceToken builderServiceToken = builderServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, builderServiceToken.getName());
        assertEquals(0, builderServiceToken.getData().length);
        assertFalse(builderServiceToken.isEncrypted());
        assertTrue(builderServiceToken.isBoundTo(MASTER_TOKEN));
        assertTrue(builderServiceToken.isBoundTo(USER_ID_TOKEN));
        
        final Set<ServiceToken> msgServiceTokens = msgBuilder.getServiceTokens();
        assertEquals(1, msgServiceTokens.size());
        final ServiceToken msgServiceToken = msgServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, msgServiceToken.getName());
        assertEquals(0, msgServiceToken.getData().length);
        assertFalse(msgServiceToken.isEncrypted());
        assertTrue(msgServiceToken.isBoundTo(MASTER_TOKEN));
        assertTrue(msgServiceToken.isBoundTo(USER_ID_TOKEN));
        
        assertTrue(tokenBuilder.addPrimaryServiceToken(serviceToken));
        assertTrue(tokenBuilder.deletePrimaryServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPrimaryServiceTokens().size());
        assertEquals(1, msgBuilder.getServiceTokens().size());
    }

    @Test
    public void deleteUnknownPrimaryServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, false, false));
        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, false));
        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, true));
    }
    
    @Test
    public void addUnboundPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertTrue(tokenBuilder.getPeerServiceTokens().isEmpty());
        
        assertTrue(tokenBuilder.addUnboundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(1, serviceTokens.size());
        final ServiceToken serviceToken = serviceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, serviceToken.getName());
        assertArrayEquals(DATA, serviceToken.getData());
        assertEquals(ENCRYPT, serviceToken.isEncrypted());
        assertTrue(serviceToken.isUnbound());
        
        assertEquals(serviceTokens, msgBuilder.getPeerServiceTokens());
    }
    
    @Test(expected = MslInternalException.class)
    public void trustedNetAddUnboundPeerServiceToken() throws MslEncodingException, MslCryptoException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(trustedNetCtx, null, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(trustedNetCtx, trustedNetMsgCtx, msgBuilder);
        
        tokenBuilder.addUnboundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO);
    }
    
    @Test
    public void noCryptoContextAddUnboundPeerServiceToken() throws MslException {
        p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
        p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);
        
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addUnboundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void addMasterBoundPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertTrue(tokenBuilder.getPeerServiceTokens().isEmpty());
        
        assertTrue(tokenBuilder.addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(1, serviceTokens.size());
        final ServiceToken serviceToken = serviceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, serviceToken.getName());
        assertArrayEquals(DATA, serviceToken.getData());
        assertEquals(ENCRYPT, serviceToken.isEncrypted());
        assertTrue(serviceToken.isBoundTo(PEER_MASTER_TOKEN));
        
        assertEquals(serviceTokens, msgBuilder.getPeerServiceTokens());
    }
    
    @Test
    public void noMasterTokenAddMasterBoundPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void noCryptoContextAddMasterBoundPeerServiceToken() throws MslEncodingException, MslCryptoException, MslException {
        p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
        p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);
        
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void trustedNetAddMasterBoundPeerServiceToken() throws MslEncodingException, MslCryptoException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(trustedNetCtx, trustedNetMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addMasterBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
    }
    
    @Test
    public void addUserBoundPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertTrue(tokenBuilder.getPeerServiceTokens().isEmpty());
        
        assertTrue(tokenBuilder.addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(1, serviceTokens.size());
        final ServiceToken serviceToken = serviceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, serviceToken.getName());
        assertArrayEquals(DATA, serviceToken.getData());
        assertEquals(ENCRYPT, serviceToken.isEncrypted());
        assertTrue(serviceToken.isBoundTo(USER_ID_TOKEN));
        
        assertEquals(serviceTokens, msgBuilder.getPeerServiceTokens());
    }
    
    @Test
    public void noMasterTokenAddUserBoundPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, null, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void noUserIdTokenAddUserBoundPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, null);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, null);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void noCryptoContextAddUserBoundPeerServiceToken() throws MslEncodingException, MslCryptoException, MslException {
        p2pMsgCtx.removeCryptoContext(TOKEN_NAME);
        p2pMsgCtx.removeCryptoContext(EMPTY_TOKEN_NAME);
        
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
        
        final Set<ServiceToken> serviceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(0, serviceTokens.size());
        assertEquals(0, msgBuilder.getServiceTokens().size());
    }
    
    @Test
    public void trustedNetAddUserBoundPeerServiceToken() throws MslEncodingException, MslCryptoException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(trustedNetCtx, MASTER_TOKEN, USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(trustedNetCtx, trustedNetMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.addUserBoundPeerServiceToken(TOKEN_NAME, DATA, ENCRYPT, COMPRESSION_ALGO));
    }
    
    @Test
    public void excludeUnboundPeerServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, null, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addPeerServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, false));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, true));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, false, false));
        assertEquals(0, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(0, msgBuilder.getPeerServiceTokens().size());
        
        assertTrue(tokenBuilder.addPeerServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePeerServiceToken(serviceToken));
        assertEquals(0, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(0, msgBuilder.getPeerServiceTokens().size());
    }
    
    @Test
    public void excludeMasterBoundPeerServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addPeerServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, false, false));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, true));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, false));
        assertEquals(0, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(0, msgBuilder.getPeerServiceTokens().size());
        
        assertTrue(tokenBuilder.addPeerServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePeerServiceToken(serviceToken));
        assertEquals(0, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(0, msgBuilder.getPeerServiceTokens().size());
    }
    
    @Test
    public void excludeUserBoundPeerServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addPeerServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, false, false));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, false));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, true));
        assertEquals(0, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(0, msgBuilder.getPeerServiceTokens().size());
        
        assertTrue(tokenBuilder.addPeerServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
        
        assertTrue(tokenBuilder.excludePeerServiceToken(serviceToken));
        assertEquals(0, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(0, msgBuilder.getPeerServiceTokens().size());
    }

    @Test
    public void excludeUnknownPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, false, false));
        assertEquals(0, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(0, msgBuilder.getPeerServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, false));
        assertEquals(0, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(0, msgBuilder.getPeerServiceTokens().size());
        
        assertFalse(tokenBuilder.excludePeerServiceToken(TOKEN_NAME, true, true));
        assertEquals(0, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(0, msgBuilder.getPeerServiceTokens().size());
    }
    
    @Test
    public void deleteUnboundPeerServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, null, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addPeerServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        
        assertFalse(tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, false));
        assertFalse(tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, true));
        assertTrue(tokenBuilder.deletePeerServiceToken(TOKEN_NAME, false, false));
        final Set<ServiceToken> builderServiceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(1, builderServiceTokens.size());
        final ServiceToken builderServiceToken = builderServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, builderServiceToken.getName());
        assertEquals(0, builderServiceToken.getData().length);
        assertFalse(builderServiceToken.isEncrypted());
        assertFalse(builderServiceToken.isMasterTokenBound());
        assertFalse(builderServiceToken.isUserIdTokenBound());
        
        final Set<ServiceToken> msgServiceTokens = msgBuilder.getPeerServiceTokens();
        assertEquals(1, msgServiceTokens.size());
        final ServiceToken msgServiceToken = msgServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, msgServiceToken.getName());
        assertEquals(0, msgServiceToken.getData().length);
        assertFalse(msgServiceToken.isEncrypted());
        assertFalse(msgServiceToken.isMasterTokenBound());
        assertFalse(msgServiceToken.isUserIdTokenBound());
        
        assertTrue(tokenBuilder.addPeerServiceToken(serviceToken));
        assertTrue(tokenBuilder.deletePeerServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
    }
    
    @Test
    public void deleteMasterBoundPeerServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, null, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addPeerServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        
        assertFalse(tokenBuilder.deletePeerServiceToken(TOKEN_NAME, false, false));
        assertFalse(tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, true));
        assertTrue(tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, false));
        final Set<ServiceToken> builderServiceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(1, builderServiceTokens.size());
        final ServiceToken builderServiceToken = builderServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, builderServiceToken.getName());
        assertEquals(0, builderServiceToken.getData().length);
        assertFalse(builderServiceToken.isEncrypted());
        assertTrue(builderServiceToken.isBoundTo(PEER_MASTER_TOKEN));
        assertFalse(builderServiceToken.isUserIdTokenBound());
        
        final Set<ServiceToken> msgServiceTokens = msgBuilder.getPeerServiceTokens();
        assertEquals(1, msgServiceTokens.size());
        final ServiceToken msgServiceToken = msgServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, msgServiceToken.getName());
        assertEquals(0, msgServiceToken.getData().length);
        assertFalse(msgServiceToken.isEncrypted());
        assertTrue(msgServiceToken.isBoundTo(PEER_MASTER_TOKEN));
        assertFalse(msgServiceToken.isUserIdTokenBound());
        
        assertTrue(tokenBuilder.addPeerServiceToken(serviceToken));
        assertTrue(tokenBuilder.deletePeerServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
    }
    
    @Test
    public void deleteUserBoundPeerServiceToken() throws MslEncodingException, MslCryptoException, MslMessageException, MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final ServiceToken serviceToken = new ServiceToken(p2pCtx, TOKEN_NAME, DATA, PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN, ENCRYPT, COMPRESSION_ALGO, new NullCryptoContext());
        msgBuilder.addPeerServiceToken(serviceToken);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        
        assertFalse(tokenBuilder.deletePeerServiceToken(TOKEN_NAME, false, false));
        assertFalse(tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, false));
        assertTrue(tokenBuilder.deletePeerServiceToken(TOKEN_NAME, true, true));
        final Set<ServiceToken> builderServiceTokens = tokenBuilder.getPeerServiceTokens();
        assertEquals(1, builderServiceTokens.size());
        final ServiceToken builderServiceToken = builderServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, builderServiceToken.getName());
        assertEquals(0, builderServiceToken.getData().length);
        assertFalse(builderServiceToken.isEncrypted());
        assertTrue(builderServiceToken.isBoundTo(PEER_MASTER_TOKEN));
        assertTrue(builderServiceToken.isBoundTo(PEER_USER_ID_TOKEN));
        
        final Set<ServiceToken> msgServiceTokens = msgBuilder.getPeerServiceTokens();
        assertEquals(1, msgServiceTokens.size());
        final ServiceToken msgServiceToken = msgServiceTokens.toArray(new ServiceToken[0])[0];
        assertEquals(TOKEN_NAME, msgServiceToken.getName());
        assertEquals(0, msgServiceToken.getData().length);
        assertFalse(msgServiceToken.isEncrypted());
        assertTrue(msgServiceToken.isBoundTo(PEER_MASTER_TOKEN));
        assertTrue(msgServiceToken.isBoundTo(PEER_USER_ID_TOKEN));
        
        assertTrue(tokenBuilder.addPeerServiceToken(serviceToken));
        assertTrue(tokenBuilder.deletePeerServiceToken(serviceToken));
        assertEquals(1, tokenBuilder.getPeerServiceTokens().size());
        assertEquals(1, msgBuilder.getPeerServiceTokens().size());
    }

    @Test
    public void deleteUnknownPeerServiceToken() throws MslException {
        final MessageBuilder msgBuilder = messageFactory.createRequest(p2pCtx, MASTER_TOKEN, USER_ID_TOKEN);
        msgBuilder.setPeerAuthTokens(PEER_MASTER_TOKEN, PEER_USER_ID_TOKEN);
        final MessageServiceTokenBuilder tokenBuilder = new MessageServiceTokenBuilder(p2pCtx, p2pMsgCtx, msgBuilder);
        
        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, false, false));
        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, false));
        assertFalse(tokenBuilder.deletePrimaryServiceToken(TOKEN_NAME, true, true));
    }
}
