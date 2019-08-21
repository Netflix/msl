/**
 * Copyright (c) 2012-2018 Netflix, Inc.  All rights reserved.
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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.ResponseCode;
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
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.MockRsaAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.entityauth.RsaAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationFactory;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.KeyResponseData;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.keyx.SymmetricWrappedExchange.KeyId;
import com.netflix.msl.msg.MessageHeader.HeaderData;
import com.netflix.msl.msg.MessageHeader.HeaderPeerData;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MockTokenFactory;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Message input stream unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MessageInputStreamTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Maximum number of payload chunks to generate. */
    private static final int MAX_PAYLOAD_CHUNKS = 12;
    /** Maximum payload chunk data size in bytes. */
    private static final int MAX_DATA_SIZE = 100 * 1024;
    /** Non-replayable ID acceptance window. */
    private static final long NON_REPLAYABLE_ID_WINDOW = 65536;

    /** Random. */
    private static Random random = new Random();
    /** Trusted network MSL context. */
    private static MslContext trustedNetCtx;
    /** Peer-to-peer MSL context. */
    private static MslContext p2pCtx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Header service token crypto contexts. */
    private static Map<String,ICryptoContext> cryptoContexts = new HashMap<String,ICryptoContext>();
    /** Message payloads (initially empty). */
    private static final List<PayloadChunk> payloads = new ArrayList<PayloadChunk>();
    /** Data read buffer. */
    private static byte[] buffer;

    private static MessageHeader MESSAGE_HEADER;
    private static ErrorHeader ERROR_HEADER;
    private static final Set<KeyRequestData> KEY_REQUEST_DATA = new HashSet<KeyRequestData>();
    private static KeyResponseData KEY_RESPONSE_DATA;
    private static ICryptoContext KEYX_CRYPTO_CONTEXT, ALT_MSL_CRYPTO_CONTEXT;

    private static final long SEQ_NO = 1;
    private static final long MSG_ID = 42;
    private static final boolean END_OF_MSG = true;
    private static final byte[] DATA = new byte[32];

    private static final String UNAUTHENTICATED_ESN = "MOCKUNAUTH-ESN";

    /**
     * A crypto context that always returns false for verify. The other crypto
     * operations are no-ops.
     */
    private static class RejectingCryptoContext extends NullCryptoContext {
        /* (non-Javadoc)
         * @see com.netflix.msl.crypto.NullCryptoContext#verify(byte[], byte[], com.netflix.msl.io.MslEncoderFactory)
         */
        @Override
        public boolean verify(final byte[] data, final byte[] signature, final MslEncoderFactory encoder) throws MslCryptoException {
            return false;
        }
    }

    /**
     * Increments the provided non-replayable ID by 1, wrapping around to zero
     * if the provided value is equal to {@link MslConstants#MAX_LONG_VALUE}.
     *
     * @param id the non-replayable ID to increment.
     * @return the non-replayable ID + 1.
     * @throws MslInternalException if the provided non-replayable ID is out of
     *         range.
     */
    private static long incrementNonReplayableId(final long id) {
        if (id < 0 || id > MslConstants.MAX_LONG_VALUE)
            throw new MslInternalException("Non-replayable ID " + id + " is outside the valid range.");
        return (id == MslConstants.MAX_LONG_VALUE) ? 0 : id + 1;
    }

    /**
     * Create a new input stream containing a MSL message constructed from the
     * provided header and payloads.
     *
     * @param header message or error header.
     * @param payloads zero or more payload chunks.
     * @return an input stream containing the MSL message.
     * @throws IOException if there is an error creating the input stream.
     * @throws MslEncoderException if there is an error encoding the data.
     */
    private static InputStream generateInputStream(final Header header, final List<PayloadChunk> payloads) throws IOException, MslEncoderException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(header.toMslEncoding(encoder, ENCODER_FORMAT));
        for (final PayloadChunk payload : payloads)
            baos.write(payload.toMslEncoding(encoder, ENCODER_FORMAT));
        return new ByteArrayInputStream(baos.toByteArray());
    }

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();

    @BeforeClass
    public static void setup() throws MslMasterTokenException, MslEntityAuthException, MslException {
        trustedNetCtx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        p2pCtx = new MockMslContext(EntityAuthenticationScheme.PSK, true);
        encoder = trustedNetCtx.getMslEncoderFactory();
        random.nextBytes(DATA);
        buffer = new byte[MAX_PAYLOAD_CHUNKS * MAX_DATA_SIZE];

        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        MESSAGE_HEADER = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);

        ERROR_HEADER =  new ErrorHeader(trustedNetCtx, entityAuthData, 1, ResponseCode.FAIL, 3, "errormsg", "usermsg");

        final KeyRequestData keyRequest = new SymmetricWrappedExchange.RequestData(KeyId.PSK);
        KEY_REQUEST_DATA.add(keyRequest);
        final KeyExchangeFactory factory = trustedNetCtx.getKeyExchangeFactory(keyRequest.getKeyExchangeScheme());
        final KeyExchangeData keyxData = factory.generateResponse(trustedNetCtx, ENCODER_FORMAT, keyRequest, entityAuthData);
        KEY_RESPONSE_DATA = keyxData.keyResponseData;
        KEYX_CRYPTO_CONTEXT = keyxData.cryptoContext;

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

    @AfterClass
    public static void teardown() {
        ALT_MSL_CRYPTO_CONTEXT = null;
        KEYX_CRYPTO_CONTEXT = null;
        KEY_RESPONSE_DATA = null;
        KEY_REQUEST_DATA.clear();
        ERROR_HEADER = null;
        MESSAGE_HEADER = null;
        buffer = null;
        encoder = null;
        p2pCtx = null;
        trustedNetCtx = null;
    }

    @Before
    public void reset() {
        payloads.clear();
    }

    @Test
    public void messageHeaderEmpty() throws MslEncodingException, MslException, IOException, MslEncoderException {
        // An end-of-message payload is expected.
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, new byte[0], cryptoContext));
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertEquals(0, mis.available());
        assertNull(mis.getErrorHeader());
        assertEquals(MESSAGE_HEADER, mis.getMessageHeader());
        assertTrue(mis.markSupported());
        assertEquals(-1, mis.read());
        assertEquals(-1, mis.read(buffer));
        assertEquals(-1, mis.read(buffer, 0, 1));
        assertEquals(0, mis.skip(1));

        mis.mark(0);
        mis.reset();
        mis.close();
    }

    @Test
    public void messageHeaderData() throws MslEncodingException, MslException, IOException, MslEncoderException {
        // An end-of-message payload is expected.
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, cryptoContext));
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertEquals(DATA.length, mis.read(buffer));
        assertArrayEquals(DATA, Arrays.copyOf(buffer, DATA.length));

        mis.close();
    }

    @Test
    public void entityAuthDataIdentity() throws MslException, IOException, MslEncoderException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertEquals(entityAuthData.getIdentity(), mis.getIdentity());

        mis.close();
    }

    @Test
    public void masterTokenIdentity() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, MslException, IOException, MslEncoderException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(trustedNetCtx, 1, 1);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertEquals(masterToken.getIdentity(), mis.getIdentity());

        mis.close();
    }

    @Test
    public void errorHeaderIdentity() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslMasterTokenException, IOException, MslException, MslEncoderException {
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final ErrorHeader errorHeader = new ErrorHeader(trustedNetCtx, entityAuthData, 1, ResponseCode.FAIL, 3, "errormsg", "usermsg");

        final InputStream is = generateInputStream(errorHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertEquals(entityAuthData.getIdentity(), mis.getIdentity());

        mis.close();
    }

    @Test
    public void revokedEntity() throws IOException, MslUserAuthException, MslKeyExchangeException, MslException, MslEncoderException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITY_REVOKED);

        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.NONE, false);
        final MockAuthenticationUtils authutils = new MockAuthenticationUtils();
        final UnauthenticatedAuthenticationFactory factory = new UnauthenticatedAuthenticationFactory(authutils);
        ctx.addEntityAuthenticationFactory(factory);

        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);

        authutils.revokeEntity(entityAuthData.getIdentity());
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void revokedMasterToken() throws IOException, MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslMasterTokenException, MslException, MslEncoderException {
        thrown.expect(MslMasterTokenException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_IDENTITY_REVOKED);

        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        final MockTokenFactory factory = new MockTokenFactory();
        ctx.setTokenFactory(factory);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        factory.setRevokedMasterToken(masterToken);
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void nullUser() throws MslEncodingException, MslEntityAuthException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslMasterTokenException, MslException, IOException, MslEncoderException {
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertNull(mis.getUser());

        mis.close();
    }

    @Test
    public void userIdTokenUser() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, MslException, IOException, MslEncoderException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(trustedNetCtx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(trustedNetCtx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, userIdToken, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertEquals(userIdToken.getUser(), mis.getUser());

        mis.close();
    }

    @Test
    public void revokedUserIdToken() throws IOException, MslUserAuthException, MslKeyExchangeException, MslUserIdTokenException, MslException, MslEncoderException {
        thrown.expect(MslUserIdTokenException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_REVOKED);

        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        final MockTokenFactory factory = new MockTokenFactory();
        ctx.setTokenFactory(factory);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, userIdToken, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        factory.setRevokedUserIdToken(userIdToken);
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void untrustedUserIdToken() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, MslUserIdTokenException, MslEncoderException, MslException, IOException {
        thrown.expect(MslUserIdTokenException.class);
        thrown.expectMessageId(MSG_ID);

        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        final MockTokenFactory factory = new MockTokenFactory();
        ctx.setTokenFactory(factory);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUntrustedUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, userIdToken, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        factory.setRevokedUserIdToken(userIdToken);
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    // FIXME This can be removed once the old handshake logic is removed.
    @Test
    public void explicitHandshake() throws IOException, MslUserAuthException, MslKeyExchangeException, MslUserIdTokenException, MslException, MslEncoderException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, true, true, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertTrue(mis.isHandshake());

        mis.close();
    }

    // FIXME This can be removed once the old handshake logic is removed.
    @Test
    public void inferredHandshake() throws MslException, IOException, MslEncoderException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);

        payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, new byte[0], messageHeader.getCryptoContext()));
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertTrue(mis.isHandshake());

        mis.close();
    }

    // FIXME This can be removed once the old handshake logic is removed.
    @Test
    public void notHandshake() throws IOException, MslException, MslEncoderException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);

        payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, messageHeader.getCryptoContext()));
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertFalse(mis.isHandshake());

        mis.close();
    }

    @Test
    public void keyExchange() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, MslException, IOException, MslEncoderException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);

        // Encrypt the payload with the key exchange crypto context.
        payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, KEYX_CRYPTO_CONTEXT));
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertEquals(DATA.length, mis.read(buffer));
        assertArrayEquals(DATA, Arrays.copyOf(buffer, DATA.length));
        assertEquals(mis.getPayloadCryptoContext(), mis.getKeyExchangeCryptoContext());

        mis.close();
    }

    @Test
    public void peerKeyExchange() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, MslException, IOException, MslEncoderException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);

        // Encrypt the payload with the key exchange crypto context.
        final ICryptoContext cryptoContext = messageHeader.getCryptoContext();
        payloads.add(new PayloadChunk(p2pCtx, SEQ_NO, MSG_ID, END_OF_MSG, null, DATA, cryptoContext));
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertEquals(DATA.length, mis.read(buffer));
        assertArrayEquals(DATA, Arrays.copyOf(buffer, DATA.length));
        assertTrue(mis.getPayloadCryptoContext() != mis.getKeyExchangeCryptoContext());

        mis.close();
    }

    @Test
    public void unsupportedKeyExchangeScheme() throws IOException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslKeyExchangeException.class);
        thrown.expectMslError(MslError.KEYX_FACTORY_NOT_FOUND);
        thrown.expectMessageId(MSG_ID);

        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        ctx.removeKeyExchangeFactories(KeyExchangeScheme.SYMMETRIC_WRAPPED);

        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void missingKeyRequestData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        // We need to replace the MSL crypto context before parsing the message
        // so create a local MSL context.
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, true);

        thrown.expect(MslKeyExchangeException.class);
        thrown.expectMslError(MslError.KEYX_RESPONSE_REQUEST_MISMATCH);
        thrown.expectMessageId(MSG_ID);

        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);

        ctx.setMslCryptoContext(new RejectingCryptoContext());
        final InputStream is = generateInputStream(messageHeader, payloads);
        final Set<KeyRequestData> keyRequestData = Collections.emptySet();
        final MessageInputStream mis = new MessageInputStream(ctx, is, keyRequestData, cryptoContexts);
        mis.close();
    }

    @Test
    public void incompatibleKeyRequestData() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslMasterTokenException, MslMessageException, MslUserAuthException, IOException, MslException, MslEncoderException {
        // We need to replace the MSL crypto context before parsing the message
        // so create a local MSL context.
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, true);

        thrown.expect(MslKeyExchangeException.class);
        thrown.expectMslError(MslError.KEYX_RESPONSE_REQUEST_MISMATCH);
        thrown.expectMessageId(MSG_ID);

        final Set<KeyRequestData> keyRequestData = new HashSet<KeyRequestData>();
        keyRequestData.add(new SymmetricWrappedExchange.RequestData(KeyId.SESSION));

        final KeyRequestData keyRequest = new SymmetricWrappedExchange.RequestData(KeyId.PSK);
        final KeyExchangeFactory factory = ctx.getKeyExchangeFactory(keyRequest.getKeyExchangeScheme());
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        final KeyExchangeData keyExchangeData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequest, entityAuthData);
        final KeyResponseData keyResponseData = keyExchangeData.keyResponseData;

        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, keyResponseData, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, entityAuthData, null, headerData, peerData);

        ctx.setMslCryptoContext(new RejectingCryptoContext());
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(ctx, is, keyRequestData, cryptoContexts);
        mis.close();
    }

    @Test
    public void oneCompatibleKeyRequestData() throws IOException, MslUserAuthException, MslException, MslEncoderException {
        // Populate the key request data such that the compatible data requires
        // iterating through one of the incompatible ones.
        final Set<KeyRequestData> keyRequestData = new HashSet<KeyRequestData>();
        final KeyRequestData keyRequest = new SymmetricWrappedExchange.RequestData(KeyId.PSK);
        keyRequestData.add(new SymmetricWrappedExchange.RequestData(KeyId.SESSION));
        keyRequestData.add(keyRequest);
        keyRequestData.add(new SymmetricWrappedExchange.RequestData(KeyId.SESSION));

        final KeyExchangeFactory factory = trustedNetCtx.getKeyExchangeFactory(keyRequest.getKeyExchangeScheme());
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final KeyExchangeData keyExchangeData = factory.generateResponse(trustedNetCtx, ENCODER_FORMAT, keyRequest, entityAuthData);
        final KeyResponseData keyResponseData = keyExchangeData.keyResponseData;

        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, keyResponseData, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, keyRequestData, cryptoContexts);
        mis.close();
    }

    @Test
    public void expiredRenewableClientMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
        final Date expiration = new Date(System.currentTimeMillis() - 10000);
        final MasterToken masterToken = new MasterToken(trustedNetCtx, renewalWindow, expiration, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
        final HeaderData headerData = new HeaderData(MSG_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void expiredRenewablePeerMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
        final Date expiration = new Date(System.currentTimeMillis() - 10000);
        final MasterToken masterToken = new MasterToken(p2pCtx, renewalWindow, expiration, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
        final HeaderData headerData = new HeaderData(MSG_ID, null, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void expiredNotRenewableClientMessage() throws IOException, MslUserAuthException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_EXPIRED_NOT_RENEWABLE);
        thrown.expectMessageId(MSG_ID);

        // Expired messages received by a trusted network server should be
        // rejected.
        final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
        final Date expiration = new Date(System.currentTimeMillis() - 10000);
        final MasterToken masterToken = new MasterToken(trustedNetCtx, renewalWindow, expiration, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void expiredNoKeyRequestDataClientMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_EXPIRED_NO_KEYREQUEST_DATA);
        thrown.expectMessageId(MSG_ID);

        // Expired renewable messages received by a trusted network server
        // with no key request data should be rejected.
        final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
        final Date expiration = new Date(System.currentTimeMillis() - 10000);
        final MasterToken masterToken = new MasterToken(trustedNetCtx, renewalWindow, expiration, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
        final HeaderData headerData = new HeaderData(MSG_ID, null, true, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void expiredNotRenewableServerMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, MslEncoderException, MslException, IOException {
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);

        // Expired messages received by a trusted network client should not be
        // rejected.
        final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
        final Date expiration = new Date(System.currentTimeMillis() - 10000);
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        // The master token's crypto context must be cached, as if the client
        // constructed it after a previous message exchange.
        final ICryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);
        ctx.getMslStore().setCryptoContext(masterToken, cryptoContext);

        // Generate the input stream. This will encode the message.
        final InputStream is = generateInputStream(messageHeader, payloads);

        // Change the MSL crypto context so the master token can no longer be
        // verified or decrypted.
        ctx.setMslCryptoContext(ALT_MSL_CRYPTO_CONTEXT);

        // Now "receive" the message with a master token that we cannot verify
        // or decrypt, but for which a cached crypto context exists.
        final MessageInputStream mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void expiredNoKeyRequestDataPeerMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_EXPIRED_NO_KEYREQUEST_DATA);
        thrown.expectMessageId(MSG_ID);

        final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
        final Date expiration = new Date(System.currentTimeMillis() - 10000);
        final MasterToken masterToken = new MasterToken(p2pCtx, renewalWindow, expiration, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
        final HeaderData headerData = new HeaderData(MSG_ID, null, true, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void expiredNotRenewablePeerMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_EXPIRED_NOT_RENEWABLE);
        thrown.expectMessageId(MSG_ID);

        final Date renewalWindow = new Date(System.currentTimeMillis() - 20000);
        final Date expiration = new Date(System.currentTimeMillis() - 10000);
        final MasterToken masterToken = new MasterToken(p2pCtx, renewalWindow, expiration, 1L, 1L, null, MockPresharedAuthenticationFactory.PSK_ESN, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void handshakeNotRenewable() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, MslUserIdTokenException, IOException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.HANDSHAKE_DATA_MISSING);
        thrown.expectMessageId(MSG_ID);

        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final HeaderData headerData = new HeaderData(MSG_ID, 1L, false, true, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void handshakeMissingKeyRequestData() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, MslUserIdTokenException, IOException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.HANDSHAKE_DATA_MISSING);
        thrown.expectMessageId(MSG_ID);

        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final HeaderData headerData = new HeaderData(MSG_ID, 1L, true, true, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void nonReplayableNoMasterTokenClientMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.INCOMPLETE_NONREPLAYABLE_MESSAGE);
        thrown.expectMessageId(MSG_ID);

        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final HeaderData headerData = new HeaderData(MSG_ID, 1L, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void nonReplayableNoMasterTokenPeerMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.INCOMPLETE_NONREPLAYABLE_MESSAGE);
        thrown.expectMessageId(MSG_ID);

        final EntityAuthenticationData entityAuthData = p2pCtx.getEntityAuthenticationData(null);
        final HeaderData headerData = new HeaderData(MSG_ID, 1L, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(p2pCtx, entityAuthData, null, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(p2pCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void nonReplayableIdEqual() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_REPLAYED);
        thrown.expectMessageId(MSG_ID);

        final long nonReplayableId = 1L;
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1L, 1L);
        final MockTokenFactory factory = new MockTokenFactory();
        factory.setLargestNonReplayableId(nonReplayableId);
        ctx.setTokenFactory(factory);

        final HeaderData headerData = new HeaderData(MSG_ID, nonReplayableId, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void nonReplayableIdSmaller() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_REPLAYED);
        thrown.expectMessageId(MSG_ID);

        final long nonReplayableId = 2L;
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1L, 1L);
        final MockTokenFactory factory = new MockTokenFactory();
        factory.setLargestNonReplayableId(nonReplayableId);
        ctx.setTokenFactory(factory);

        final HeaderData headerData = new HeaderData(MSG_ID, nonReplayableId - 1, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void nonReplayableIdOutsideWindow() throws IOException, MslUserAuthException, MslKeyExchangeException, MslException, MslEncoderException {
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1L, 1L);
        final MockTokenFactory factory = new MockTokenFactory();
        ctx.setTokenFactory(factory);

        long largestNonReplayableId = MslConstants.MAX_LONG_VALUE - NON_REPLAYABLE_ID_WINDOW - 1;
        long nonReplayableId = MslConstants.MAX_LONG_VALUE;
        for (int i = 0; i < 2; ++i) {
            MessageInputStream mis = null;
            try {
                factory.setLargestNonReplayableId(largestNonReplayableId);

                final HeaderData headerData = new HeaderData(MSG_ID, nonReplayableId, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
                final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
                final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

                final InputStream is = generateInputStream(messageHeader, payloads);
                mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
                fail(i + ": Non-replayable ID " + nonReplayableId + " accepted with largest non-replayable ID " + largestNonReplayableId);
            } catch (final MslMessageException e) {
                assertEquals(MslError.MESSAGE_REPLAYED_UNRECOVERABLE, e.getError());
                assertEquals((Long)MSG_ID, e.getMessageId());
            } finally {
                if (mis != null) mis.close();
            }

            largestNonReplayableId = incrementNonReplayableId(largestNonReplayableId);
            nonReplayableId = incrementNonReplayableId(nonReplayableId);
        }
    }

    @Test
    public void nonReplayableIdInsideWindow() throws MslUserAuthException, MslKeyExchangeException, MslException, IOException, MslEncoderException {
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1L, 1L);
        final MockTokenFactory factory = new MockTokenFactory();
        ctx.setTokenFactory(factory);

        long largestNonReplayableId = MslConstants.MAX_LONG_VALUE - NON_REPLAYABLE_ID_WINDOW;
        long nonReplayableId = MslConstants.MAX_LONG_VALUE;
        for (int i = 0; i < NON_REPLAYABLE_ID_WINDOW + 1; ++i) {
            MessageInputStream mis = null;
            try {
                factory.setLargestNonReplayableId(largestNonReplayableId);

                final HeaderData headerData = new HeaderData(MSG_ID, nonReplayableId, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
                final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
                final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

                final InputStream is = generateInputStream(messageHeader, payloads);
                mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
            } catch (final MslMessageException e) {
                fail(i + ": Non-replayable ID " + nonReplayableId + " rejected with largest non-replayable ID " + largestNonReplayableId);
            } finally {
                if (mis != null) mis.close();
            }

            largestNonReplayableId = incrementNonReplayableId(largestNonReplayableId);
            nonReplayableId = incrementNonReplayableId(nonReplayableId);
        }
    }

    @Test
    public void replayedClientMessage() throws MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_REPLAYED);
        thrown.expectMessageId(MSG_ID);

        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1L, 1L);
        final MockTokenFactory factory = new MockTokenFactory();
        factory.setLargestNonReplayableId(1L);
        ctx.setTokenFactory(factory);

        final HeaderData headerData = new HeaderData(MSG_ID, 1L, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void replayedPeerMessage() throws MslEncodingException, MslCryptoException, MslMasterTokenException, MslEntityAuthException, MslMessageException, MslUserAuthException, MslKeyExchangeException, IOException, MslException, MslEncoderException {
        thrown.expect(MslMessageException.class);
        thrown.expectMslError(MslError.MESSAGE_REPLAYED);
        thrown.expectMessageId(MSG_ID);

        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, true);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1L, 1L);
        final MockTokenFactory factory = new MockTokenFactory();
        factory.setLargestNonReplayableId(1L);
        ctx.setTokenFactory(factory);

        final HeaderData headerData = new HeaderData(MSG_ID, 1L, true, false, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(ctx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(ctx, is, KEY_REQUEST_DATA, cryptoContexts);
        mis.close();
    }

    @Test
    public void errorHeader() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslException, IOException, MslEncoderException {
        final InputStream is = generateInputStream(ERROR_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        assertEquals(0, mis.available());
        assertEquals(ERROR_HEADER, mis.getErrorHeader());
        assertNull(mis.getMessageHeader());
        assertTrue(mis.markSupported());

        mis.mark(0);
        mis.reset();
        mis.close();
    }

    @Test(expected = MslInternalException.class)
    public void readFromError() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslException, IOException, MslEncoderException {
        final InputStream is = generateInputStream(ERROR_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        try {
            mis.read(buffer);
        } finally {
            mis.close();
        }
    }

    @Test
    public void readFromHandshakeMessage() throws IOException, MslUserAuthException, MslKeyExchangeException, MslUserIdTokenException, MslException, MslEncoderException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, true, true, null, KEY_REQUEST_DATA, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = trustedNetCtx.getEntityAuthenticationData(null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        final int read = mis.read();
        assertEquals(-1, read);
        mis.close();
    }

    @Test
    public void missingEndOfMessage() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslException, IOException, MslEncoderException {
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        // If there's nothing left we'll receive end of message anyway.
        assertEquals(-1, mis.read(buffer));

        mis.close();
    }
    
    @Test
    public void entityAuthSchemeEncrypts() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertTrue(mis.encryptsPayloads());
        mis.close();
    }
    
    @Test
    public void entityAuthSchemeDoesNotEncrypt() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertFalse(mis.encryptsPayloads());
        mis.close();
    }
    
    @Test
    public void entityAuthSchemeIntegrityProtects() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertTrue(mis.protectsPayloadIntegrity());
        mis.close();
    }
    
    @Test
    public void entityAuthSchemeDoesNotIntegrityProtect() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertFalse(mis.protectsPayloadIntegrity());
        mis.close();
    }
    
    @Test
    public void entityAuthSchemeKeyxEncrypts() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertTrue(mis.encryptsPayloads());
        mis.close();
    }
    
    @Test
    public void entityAuthSchemeKeyxIntegrityProtects() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertTrue(mis.protectsPayloadIntegrity());
        mis.close();
    }
    
    @Test
    public void entitAuthSchemeDoesNotKeyxEncrypts() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertTrue(mis.encryptsPayloads());
        mis.close();
    }
    
    @Test
    public void entityAuthSchemeDoesNotKeyxIntegrityProtects() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final EntityAuthenticationData entityAuthData = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, entityAuthData, null, headerData, peerData);
        
        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertTrue(mis.protectsPayloadIntegrity());
        mis.close();
    }
    
    @Test
    public void masterTokenEncrypts() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(trustedNetCtx, 1, 1);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertTrue(mis.encryptsPayloads());
        mis.close();
    }
    
    @Test
    public void masterTokenIntegrityProtects() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(trustedNetCtx, 1, 1);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, null, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertTrue(mis.protectsPayloadIntegrity());
        mis.close();
    }
    
    @Test
    public void masterTokenKeyxEncrypts() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(trustedNetCtx, 1, 1);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertTrue(mis.encryptsPayloads());
        mis.close();
    }
    
    @Test
    public void masterTokenKeyxIntegrityProtects() throws IOException, MslEncoderException, MslUserAuthException, MslMessageException, MslKeyExchangeException, MslUserIdTokenException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(trustedNetCtx, 1, 1);
        final HeaderData headerData = new HeaderData(MSG_ID, null, false, false, null, null, KEY_RESPONSE_DATA, null, null, null);
        final HeaderPeerData peerData = new HeaderPeerData(null, null, null);
        final MessageHeader messageHeader = new MessageHeader(trustedNetCtx, null, masterToken, headerData, peerData);

        final InputStream is = generateInputStream(messageHeader, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);
        assertTrue(mis.protectsPayloadIntegrity());
        mis.close();
    }

    @Test
    public void prematureEndOfMessage() throws MslCryptoException, MslEncodingException, MslException, IOException, MslEncoderException {
        // Payloads after an end of message are ignored.
        final int extraPayloads = MAX_PAYLOAD_CHUNKS / 2;
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
            final byte[] data = new byte[random.nextInt(MAX_DATA_SIZE) + 1];
            random.nextBytes(data);
            if (i < extraPayloads) {
                payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == extraPayloads - 1), null, data, cryptoContext));
                baos.write(data);
            } else {
                payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO + i, MSG_ID, false, null, data, cryptoContext));
            }
        }
        final byte[] appdata = baos.toByteArray();
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        // Read everything. We shouldn't get any of the extra payloads.
        assertEquals(appdata.length, mis.read(buffer));
        assertArrayEquals(appdata, Arrays.copyOfRange(buffer, 0, appdata.length));

        mis.close();
    }

    @Test
    public void mismatchedMessageId() throws MslCryptoException, MslEncodingException, MslException, IOException, MslEncoderException {
        // Payloads with an incorrect message ID should be skipped.
        int badPayloads = 0;
        long sequenceNumber = SEQ_NO;
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
            final byte[] data = new byte[random.nextInt(MAX_DATA_SIZE) + 1];
            random.nextBytes(data);
            if (random.nextBoolean()) {
                payloads.add(new PayloadChunk(trustedNetCtx, sequenceNumber++, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext));
                baos.write(data);
            } else {
                payloads.add(new PayloadChunk(trustedNetCtx, sequenceNumber, 2 * MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext));
                ++badPayloads;
            }
        }
        final byte[] appdata = baos.toByteArray();
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        // Read everything. Each bad payload should throw an exception.
        int offset = 0;
        int caughtExceptions = 0;
        while (true) {
            try {
                final int bytesRead = mis.read(buffer, offset, buffer.length - offset);
                if (bytesRead == -1) break;
                offset += bytesRead;
            } catch (final IOException e) {
                ++caughtExceptions;
            }
        }
        assertEquals(badPayloads, caughtExceptions);
        assertArrayEquals(appdata, Arrays.copyOfRange(buffer, 0, appdata.length));

        mis.close();
    }

    @Test
    public void incorrectSequenceNumber() throws MslCryptoException, MslEncodingException, MslException, IOException, MslEncoderException {
        // Payloads with an incorrect sequence number should be skipped.
        int badPayloads = 0;
        long sequenceNumber = SEQ_NO;
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
            final byte[] data = new byte[random.nextInt(MAX_DATA_SIZE) + 1];
            random.nextBytes(data);
            if (random.nextBoolean()) {
                payloads.add(new PayloadChunk(trustedNetCtx, sequenceNumber++, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext));
                baos.write(data);
            } else {
                payloads.add(new PayloadChunk(trustedNetCtx, 2 * sequenceNumber + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext));
                ++badPayloads;
            }
        }
        final byte[] appdata = baos.toByteArray();
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        // Read everything. Each bad payload should throw an exception.
        int offset = 0;
        int caughtExceptions = 0;
        while (true) {
            try {
                final int bytesRead = mis.read(buffer, offset, buffer.length - offset);
                if (bytesRead == -1) break;
                offset += bytesRead;
            } catch (final IOException e) {
                ++caughtExceptions;
            }
        }
        assertEquals(badPayloads, caughtExceptions);
        assertArrayEquals(appdata, Arrays.copyOfRange(buffer, 0, appdata.length));

        mis.close();
    }

    @Test
    public void markReset() throws MslEncodingException, MslCryptoException, MslException, IOException, MslEncoderException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
            final byte[] data = new byte[random.nextInt(MAX_DATA_SIZE) + 1];
            random.nextBytes(data);
            payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext));
            baos.write(data);
        }
        final byte[] appdata = baos.toByteArray();
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        // Mark and reset to the beginning.
        final int beginningOffset = 0;
        final int beginningLength = appdata.length / 4;
        final int beginningTo = beginningOffset + beginningLength;
        final byte[] expectedBeginning = Arrays.copyOfRange(appdata, beginningOffset, beginningTo);
        mis.mark(appdata.length);
        assertEquals(expectedBeginning.length, mis.read(buffer, beginningOffset, beginningLength));
        assertArrayEquals(expectedBeginning, Arrays.copyOfRange(buffer, beginningOffset, beginningTo));
        mis.reset();
        assertEquals(expectedBeginning.length, mis.read(buffer, beginningOffset, beginningLength));
        assertArrayEquals(expectedBeginning, Arrays.copyOfRange(buffer, beginningOffset, beginningTo));

        // Mark and reset from where we are.
        final int middleOffset = beginningTo;
        final int middleLength = appdata.length / 4;
        final int middleTo = middleOffset + middleLength;
        final byte[] expectedMiddle = Arrays.copyOfRange(appdata, middleOffset, middleTo);
        mis.mark(appdata.length);
        assertEquals(expectedMiddle.length, mis.read(buffer, middleOffset, middleLength));
        assertArrayEquals(expectedMiddle, Arrays.copyOfRange(buffer, middleOffset, middleTo));
        mis.reset();
        assertEquals(expectedMiddle.length, mis.read(buffer, middleOffset, middleLength));
        assertArrayEquals(expectedMiddle, Arrays.copyOfRange(buffer, middleOffset, middleTo));

        // Mark and reset the remainder.
        final int endingOffset = middleTo;
        final int endingLength = appdata.length - middleLength - beginningLength;
        final int endingTo = endingOffset + endingLength;
        final byte[] expectedEnding = Arrays.copyOfRange(appdata, endingOffset, endingTo);
        mis.mark(appdata.length);
        assertEquals(expectedEnding.length, mis.read(buffer, endingOffset, endingLength));
        assertArrayEquals(expectedEnding, Arrays.copyOfRange(buffer, endingOffset, endingTo));
        mis.reset();
        assertEquals(expectedEnding.length, mis.read(buffer, endingOffset, endingLength));
        assertArrayEquals(expectedEnding, Arrays.copyOfRange(buffer, endingOffset, endingTo));

        // Confirm equality.
        assertArrayEquals(appdata, Arrays.copyOfRange(buffer, 0, appdata.length));

        mis.close();
    }

    @Test
    public void markResetShortMark() throws IOException, MslEncodingException, MslEntityAuthException, MslUserAuthException, MslException, MslEncoderException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
            final byte[] data = new byte[random.nextInt(MAX_DATA_SIZE) + 1];
            random.nextBytes(data);
            payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext));
            baos.write(data);
        }
        final byte[] appdata = baos.toByteArray();
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        // Mark and reset to the beginning.
        final int beginningOffset = 0;
        final int beginningLength = appdata.length / 2;
        final int beginningTo = beginningOffset + beginningLength;
        final byte[] expectedBeginning = Arrays.copyOfRange(appdata, beginningOffset, beginningTo);
        mis.mark(appdata.length);
        assertEquals(expectedBeginning.length, mis.read(buffer, beginningOffset, beginningLength));
        assertArrayEquals(expectedBeginning, Arrays.copyOfRange(buffer, beginningOffset, beginningTo));
        mis.reset();

        // Read a little bit, and mark again so we drop one or more payloads
        // but are likely to have more than one payload remaining.
        final byte[] reread = new byte[appdata.length / 4];
        assertEquals(reread.length, mis.read(reread));
        mis.mark(appdata.length);

        // Read the remainder, reset, and re-read to confirm.
        final int endingOffset = reread.length;
        final int endingLength = appdata.length - endingOffset;
        final int endingTo = endingOffset + endingLength;
        final byte[] expectedEnding = Arrays.copyOfRange(appdata, endingOffset, endingTo);
        assertEquals(expectedEnding.length, mis.read(buffer, endingOffset, endingLength));
        assertArrayEquals(expectedEnding, Arrays.copyOfRange(buffer, endingOffset, endingTo));
        mis.reset();
        assertEquals(expectedEnding.length, mis.read(buffer, endingOffset, endingLength));
        assertArrayEquals(expectedEnding, Arrays.copyOfRange(buffer, endingOffset, endingTo));

        // Confirm equality.
        assertArrayEquals(appdata, Arrays.copyOfRange(buffer, 0, appdata.length));

        mis.close();
    }

    @Test
    public void markOneReadLimit() throws IOException, MslEncodingException, MslEntityAuthException, MslUserAuthException, MslException, MslEncoderException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
            final byte[] data = new byte[random.nextInt(MAX_DATA_SIZE) + 1];
            random.nextBytes(data);
            payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext));
            baos.write(data);
        }
        final byte[] appdata = baos.toByteArray();
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        // Mark one byte and reset to the beginning.
        final byte expectedOne = appdata[0];
        mis.mark(1);
        assertEquals(expectedOne, mis.read());
        mis.reset();

        // Read a little bit and reset (which should not work).
        final int beginningOffset = 0;
        final int beginningLength = appdata.length / 2;
        final int beginningTo = beginningOffset + beginningLength;
        final byte[] expectedBeginning = Arrays.copyOfRange(appdata, beginningOffset, beginningTo);
        assertEquals(expectedBeginning.length, mis.read(buffer, beginningOffset, beginningLength));
        assertArrayEquals(expectedBeginning, Arrays.copyOfRange(buffer, beginningOffset, beginningTo));
        mis.reset();

        // Read the remainder.
        final int endingOffset = beginningLength;
        final int endingLength = appdata.length - endingOffset;
        final int endingTo = endingOffset + endingLength;
        final byte[] expectedEnding = Arrays.copyOfRange(appdata, endingOffset, endingTo);
        assertEquals(expectedEnding.length, mis.read(buffer, endingOffset, endingLength));
        assertArrayEquals(expectedEnding, Arrays.copyOfRange(buffer, endingOffset, endingTo));

        // Confirm equality.
        assertArrayEquals(appdata, Arrays.copyOfRange(buffer, 0, appdata.length));

        // Confirm end-of-stream.
        assertEquals(-1, mis.read());

        mis.close();
    }

    @Test
    public void markReadLimit() throws IOException, MslEncodingException, MslEntityAuthException, MslUserAuthException, MslException, MslEncoderException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
            final byte[] data = new byte[random.nextInt(MAX_DATA_SIZE) + 1];
            random.nextBytes(data);
            payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext));
            baos.write(data);
        }
        final byte[] appdata = baos.toByteArray();
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        // Read a little bit and mark with a short read limit.
        final int beginningOffset = 0;
        final int beginningLength = appdata.length / 4;
        final int beginningTo = beginningOffset + beginningLength;
        final byte[] expectedBeginning = Arrays.copyOfRange(appdata, beginningOffset, beginningTo);
        assertEquals(expectedBeginning.length, mis.read(buffer, beginningOffset, beginningLength));
        assertArrayEquals(expectedBeginning, Arrays.copyOfRange(buffer, beginningOffset, beginningTo));
        final int readlimit = appdata.length / 8;
        mis.mark(readlimit);

        // Read up to the read limit.
        final int readOffset = beginningLength;
        final int readLength = readlimit;
        final int readTo = readOffset + readLength;
        final byte[] expectedRead = Arrays.copyOfRange(appdata, readOffset, readTo);
        assertEquals(expectedRead.length, mis.read(buffer, readOffset, readLength));
        assertArrayEquals(expectedRead, Arrays.copyOfRange(buffer, readOffset, readTo));

        // Reset and re-read.
        mis.reset();
        assertEquals(expectedRead.length, mis.read(buffer, readOffset, readLength));
        assertArrayEquals(expectedRead, Arrays.copyOfRange(buffer, readOffset, readTo));

        // Reset and re-read.
        mis.reset();
        assertEquals(expectedRead.length, mis.read(buffer, readOffset, readLength));
        assertArrayEquals(expectedRead, Arrays.copyOfRange(buffer, readOffset, readTo));

        // Reset and read past the read limit.
        mis.reset();
        final int readPastOffset = beginningLength;
        final int readPastLength = readlimit + 1;
        final int readPastTo = readPastOffset + readPastLength;
        final byte[] expectedReadPast = Arrays.copyOfRange(appdata, readPastOffset, readPastTo);
        assertEquals(expectedReadPast.length, mis.read(buffer, readPastOffset, readPastLength));
        assertArrayEquals(expectedReadPast, Arrays.copyOfRange(buffer, readPastOffset, readPastTo));

        // Reset and confirm it did not work.
        mis.reset();
        final int endingOffset = readPastTo;
        final int endingLength = appdata.length - endingOffset;
        final int endingTo = appdata.length;
        final byte[] expectedEnding = Arrays.copyOfRange(appdata, endingOffset, endingTo);
        assertEquals(expectedEnding.length, mis.read(buffer, endingOffset, endingLength));
        assertArrayEquals(expectedEnding, Arrays.copyOfRange(buffer, endingOffset, endingTo));

        // Confirm equality.
        assertArrayEquals(appdata, Arrays.copyOfRange(buffer, 0, appdata.length));

        // Confirm end-of-stream.
        assertEquals(-1, mis.read());

        mis.close();
    }

    @Test
    public void available() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslUserAuthException, MslException, IOException, MslEncoderException {
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
            final byte[] data = new byte[random.nextInt(MAX_DATA_SIZE) + 1];
            random.nextBytes(data);
            payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext));
        }
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        // The remainder of a payload should be available, once the payload is
        // processed.
        final int firstLength = payloads.get(0).getData().length;
        mis.read();
        assertEquals(firstLength - 1, mis.available());

        // Mark and read the remainder. Nothing should be available.
        mis.mark(buffer.length);
        final int bytesRead = mis.read(buffer);
        assertEquals(0, mis.available());

        // Reset. Everything except for the original one byte should be
        // available.
        mis.reset();
        assertEquals(bytesRead, mis.available());

        // Read a little bit. Reset. Confirm the amount available.
        final int shortRead = mis.read(buffer, 0, bytesRead / 10);
        assertEquals(bytesRead - shortRead, mis.available());

        mis.close();
    }

    @Test
    public void skipAvailable() throws MslCryptoException, MslEncodingException, MslException, IOException, MslEncoderException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        for (int i = 0; i < MAX_PAYLOAD_CHUNKS; ++i) {
            final byte[] data = new byte[random.nextInt(MAX_DATA_SIZE) + 1];
            random.nextBytes(data);
            payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO + i, MSG_ID, (i == MAX_PAYLOAD_CHUNKS - 1), null, data, cryptoContext));
            baos.write(data);
        }
        final byte[] appdata = baos.toByteArray();
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        // Mark and then skip some data.
        mis.mark(appdata.length);
        final int skipLength = appdata.length / 6;
        assertEquals(skipLength, mis.skip(skipLength));

        // Confirm availability equal to the current payload's remaining data.
        int consumedBytes = 0;
        final ListIterator<PayloadChunk> chunks = payloads.listIterator();
        while (consumedBytes < skipLength && chunks.hasNext()) {
            final PayloadChunk payload = chunks.next();
            consumedBytes += payload.getData().length;
        }
        assertEquals(consumedBytes - skipLength, mis.available());

        // Read and skip for a while.
        int skipped = skipLength;
        while (skipped < appdata.length) {
            final int readLength = Math.min(appdata.length / 6, appdata.length - skipped);
            final int readTo = skipped + readLength;
            final byte[] expected = Arrays.copyOfRange(appdata, skipped, readTo);
            assertEquals(expected.length, mis.read(buffer, skipped, readLength));
            assertArrayEquals(expected, Arrays.copyOfRange(buffer, skipped, readTo));
            skipped += expected.length;

            // Confirm availability equal to the current payload's remaining
            // data.
            while (consumedBytes < skipped && chunks.hasNext()) {
                final PayloadChunk payload = chunks.next();
                consumedBytes += payload.getData().length;
            }
            assertEquals(consumedBytes - skipped, mis.available());
        }

        // Reset and redo the read and skips now that the data is buffered.
        mis.reset();
        skipped = 0;
        while (skipped < appdata.length) {
            final int readLength = Math.min(appdata.length / 6, appdata.length - skipped);
            final int readTo = skipped + readLength;
            final byte[] expected = Arrays.copyOfRange(appdata, skipped, readTo);
            assertEquals(expected.length, mis.read(buffer, skipped, readLength));
            assertArrayEquals(expected, Arrays.copyOfRange(buffer, skipped, readTo));
            skipped += expected.length;

            // Confirm availability equal to the remaining data.
            assertEquals(appdata.length - skipped, mis.available());
        }

        // Confirm equality.
        assertArrayEquals(appdata, Arrays.copyOfRange(buffer, 0, appdata.length));

        mis.close();
    }

    @Test
    public void largePayload() throws MslEncodingException, MslException, IOException, MslEncoderException {
        final ICryptoContext cryptoContext = MESSAGE_HEADER.getCryptoContext();
        final byte[] data = new byte[10 * 1024 * 1024];
        random.nextBytes(data);
        payloads.add(new PayloadChunk(trustedNetCtx, SEQ_NO, MSG_ID, true, null, data, cryptoContext));
        final InputStream is = generateInputStream(MESSAGE_HEADER, payloads);
        final MessageInputStream mis = new MessageInputStream(trustedNetCtx, is, KEY_REQUEST_DATA, cryptoContexts);

        final byte[] copy = new byte[data.length];
        assertEquals(copy.length, mis.read(copy));
        assertEquals(-1, mis.read());
        assertArrayEquals(data, copy);

        mis.close();
    }
}
