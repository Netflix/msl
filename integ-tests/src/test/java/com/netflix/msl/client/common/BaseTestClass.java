/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.client.common;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLConnection;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.client.assertable.ErrorHdrAssertable;
import com.netflix.msl.client.assertable.MsgAssertable;
import com.netflix.msl.client.configuration.ClientConfiguration;
import com.netflix.msl.client.configuration.util.ClientMslContext;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.MessageBuilder;
import com.netflix.msl.msg.MessageHeader;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;

/**
 * User: skommidi
 * Date: 7/25/14
 */
public class BaseTestClass {

    private static final long SERIAL_NUMBER = 42;
    private static final String SERVICE_TOKEN_NAME = "serviceTokenName";
    private static final ICryptoContext NULL_CRYPTO_CONTEXT = new NullCryptoContext();
    private static JSONObject ISSUER_DATA;
    protected static final String IDENTITY = MockPresharedAuthenticationFactory.PSK_ESN;
    protected static final SecretKey ENCRYPTION_KEY = MockPresharedAuthenticationFactory.KPE;
    protected static final SecretKey HMAC_KEY = MockPresharedAuthenticationFactory.KPH;
    private static final MslUser USER = MockEmailPasswordAuthenticationFactory.USER;

    /** MSL encryption key. */
    private static final byte[] MSL_ENCRYPTION_KEY = {
            (byte)0x1d, (byte)0x58, (byte)0xf3, (byte)0xb8, (byte)0xf7, (byte)0x47, (byte)0xd1, (byte)0x6a,
            (byte)0xb1, (byte)0x93, (byte)0xc4, (byte)0xc0, (byte)0xa6, (byte)0x24, (byte)0xea, (byte)0xcf,
    };
    /** MSL HMAC key. */
    private static final byte[] MSL_HMAC_KEY = {
            (byte)0xd7, (byte)0xae, (byte)0xbf, (byte)0xd5, (byte)0x87, (byte)0x9b, (byte)0xb0, (byte)0xe0,
            (byte)0xad, (byte)0x01, (byte)0x6a, (byte)0x4c, (byte)0xf3, (byte)0xcb, (byte)0x39, (byte)0x82,
            (byte)0xf5, (byte)0xba, (byte)0x26, (byte)0x0d, (byte)0xa5, (byte)0x20, (byte)0x24, (byte)0x5b,
            (byte)0xb4, (byte)0x22, (byte)0x75, (byte)0xbd, (byte)0x79, (byte)0x47, (byte)0x37, (byte)0x0c,
    };
    /** MSL wrapping key. */
    private static final byte[] MSL_WRAPPING_KEY = {
            (byte)0x83, (byte)0xb6, (byte)0x9a, (byte)0x15, (byte)0x80, (byte)0xd3, (byte)0x23, (byte)0xa2,
            (byte)0xe7, (byte)0x9d, (byte)0xd9, (byte)0xb2, (byte)0x26, (byte)0x26, (byte)0xb3, (byte)0xf6,
    };

    private String remoteEntityUrl;
    protected ClientConfiguration clientConfig;
    protected ICryptoContext serverMslCryptoContext;

    public void setServerMslCryptoContext() {
        final SecretKey mslEncryptionKey = new SecretKeySpec(MSL_ENCRYPTION_KEY, JcaAlgorithm.AES);
        final SecretKey mslHmacKey = new SecretKeySpec(MSL_HMAC_KEY, JcaAlgorithm.HMAC_SHA256);
        final SecretKey mslWrappingKey = new SecretKeySpec(MSL_WRAPPING_KEY, JcaAlgorithm.AESKW);
        serverMslCryptoContext = new SymmetricCryptoContext(clientConfig.getMslContext(), "TestMslKeys", mslEncryptionKey, mslHmacKey, mslWrappingKey);
    }

    public void loadProperties() throws IOException {
        Properties prop = new Properties();
        prop.load(BaseTestClass.class.getClassLoader().getResourceAsStream("test.properties"));

        String grettyHttpPort = System.getProperty("gretty.httpPort");
        String grettyContextPath = System.getProperty("gretty.contextPath");
        if (grettyHttpPort != null && grettyContextPath != null) {
            // By definition, Gretty is localhost
            setRemoteEntityUrl("localhost:" + grettyHttpPort + grettyContextPath);
        } else {
            // Fallback to test.properties
            setRemoteEntityUrl(prop.getProperty("remoteEntityUrl"));
        }
    }

    public String getRemoteEntityUrl() {
        return remoteEntityUrl;
    }

    private void setRemoteEntityUrl(String remoteEntityUrl) {
        this.remoteEntityUrl = remoteEntityUrl;
    }

    public static MsgAssertable thenThe(MessageInputStream msg) {
        return new MsgAssertable(msg);
    }

    public static ErrorHdrAssertable thenTheErr(MessageInputStream msg) {
        return new ErrorHdrAssertable(msg);
    }

    protected MasterToken getInitialMasterToken(final int timeOut) throws ExecutionException, InterruptedException {
        MessageInputStream message = sendReceive(timeOut);
        MasterToken initialMasterToken = message.getMessageHeader().getKeyResponseData().getMasterToken();

        return initialMasterToken;
    }

    /**
     * get master token with given renewal window and expiration.
     */
    protected MasterToken getMasterToken(final Date renewalWindow, final Date expiration, final int timeOut, final int sequenceNumberOffset) throws ExecutionException, InterruptedException, MslCryptoException, MslEncodingException, MslMasterTokenException {
        MasterToken initialMasterToken = getInitialMasterToken(timeOut);

        ClientMslContext mslContext = clientConfig.getMslContext();

        // Temporarily switch to server crypto context to create master token
        mslContext.setMslCryptoContext(serverMslCryptoContext);

        // create master token with server crypto context; mocking server
        final MasterToken masterToken = new MasterToken(mslContext, renewalWindow, expiration,
                initialMasterToken.getSequenceNumber() + sequenceNumberOffset, SERIAL_NUMBER, ISSUER_DATA, IDENTITY, ENCRYPTION_KEY, HMAC_KEY);

        // Store corresponding session crypto context of the mastertoken
        final ICryptoContext sessionCryptoContext = new SessionCryptoContext(mslContext, masterToken);
        mslContext.getMslStore().setCryptoContext(masterToken, sessionCryptoContext);

        // switch back to client crypto context after creating master token
        mslContext.setClientCryptoContext();

        return masterToken;
    }

    /**
     * get user id token with given renewal window and expiration.
     */
    protected UserIdToken getUserIdToken(final MasterToken initialMasterToken, final Date renewalWindow, final Date expiration, final int timeOut) throws ExecutionException, InterruptedException, MslCryptoException, MslEncodingException {

        ClientMslContext mslContext = clientConfig.getMslContext();

        // Temporarily switch to server crypto context to create master token
        mslContext.setMslCryptoContext(serverMslCryptoContext);

        final UserIdToken userIdToken = new UserIdToken(mslContext, renewalWindow, expiration, initialMasterToken, SERIAL_NUMBER, ISSUER_DATA, USER);

        // switch back to client crypto context after creating master token
        mslContext.setClientCryptoContext();

        return userIdToken;
    }

    /**
     * get service token bound to given master token and user id token
     */
    protected Set<ServiceToken> getServiceToken(MasterToken masterToken, UserIdToken userIdToken, ServiceTokenType serviceTokenType, boolean withData) throws MslException {
        final Random random = new Random();
        final Set<ServiceToken> serviceTokens = new HashSet<ServiceToken>();
        final byte[] data;
        if(withData) {
            data = new byte[32];
            random.nextBytes(data);
        }
        else {
            data = new byte[0];
        }

        ClientMslContext ctx = clientConfig.getMslContext();
        switch(serviceTokenType) {
            case BOTH:
                serviceTokens.add(new ServiceToken(ctx, SERVICE_TOKEN_NAME + "Both", data, masterToken, userIdToken, false, null, NULL_CRYPTO_CONTEXT));
                break;
            case MASTER_BOUND:
                serviceTokens.add(new ServiceToken(ctx, SERVICE_TOKEN_NAME + "Master", data, masterToken, null, false, null, NULL_CRYPTO_CONTEXT));
                break;
            case NONE:
                serviceTokens.add(new ServiceToken(ctx, SERVICE_TOKEN_NAME + "None", data, null, null, false, null, NULL_CRYPTO_CONTEXT));
                break;
            default:
                throw new IllegalArgumentException("Unexpected ServiceTokenType " + serviceTokenType);
        }

        return serviceTokens;
    }

    public MessageInputStream sendReceive(int timeOut) throws ExecutionException, InterruptedException {
        Future<MslControl.MslChannel> mslChannelFuture = clientConfig.getMslControl().request(clientConfig.getMslContext(),
                clientConfig.getMessageContext(),
                clientConfig.getRemoteEntity(),
                timeOut);

        if(mslChannelFuture.isDone()) {
            MslControl.MslChannel mslChannel = mslChannelFuture.get();
            return mslChannel.input;
        }

        return null;
    }

    public MessageInputStream sendReceive(final OutputStream out, final DelayedInputStream in,
                                          final MasterToken masterToken, final UserIdToken userIdToken, final Set<ServiceToken> serviceTokens,
                                          final boolean isRenewable, final boolean addKeyRequestData) throws MslException, IOException {
        final MessageBuilder builder = MessageBuilder.createRequest(clientConfig.getMslContext(), masterToken, userIdToken, null);
        builder.setRenewable(isRenewable);
        builder.setNonReplayable(clientConfig.getMessageContext().isNonReplayable());

        if(addKeyRequestData) {
            Set<KeyRequestData> keyRequestDataSet = clientConfig.getMessageContext().getKeyRequestData();
            for(KeyRequestData keyRequestData : keyRequestDataSet) {
                builder.addKeyRequestData(keyRequestData);
            }
        }

        if(serviceTokens != null) {
            for(ServiceToken serviceToken : serviceTokens) {
                builder.addServiceToken(serviceToken);
            }
        }

        final MessageHeader requestHeader = builder.getHeader();

        final MessageOutputStream request = new MessageOutputStream(clientConfig.getMslContext(), out, MslConstants.DEFAULT_CHARSET, requestHeader, requestHeader.getCryptoContext());
        clientConfig.getMessageContext().write(request);

        final MessageInputStream response = new MessageInputStream(clientConfig.getMslContext(), in, MslConstants.DEFAULT_CHARSET,
                clientConfig.getMessageContext().getKeyRequestData(), clientConfig.getMessageContext().getCryptoContexts());

        return response;
    }

    /**
     * Types of service token
     */
    protected enum ServiceTokenType {
        MASTER_BOUND,
        BOTH,
        NONE
    }

    /**
     * A delayed input stream does not open the real input stream until
     * one of its methods is called.
     */
    protected static class DelayedInputStream extends FilterInputStream {
        /**
         * Create a new delayed input stream that will not attempt to
         * construct the input stream from the URL connection until it is
         * actually needed (i.e. read from).
         *
         * @param conn backing URL connection.
         */
        public DelayedInputStream(final URLConnection conn) {
            super(null);
            this.conn = conn;
        }

        @Override
        public int available() throws IOException {
            if (in == null)
                in = conn.getInputStream();
            return super.available();
        }

        @Override
        public void close() throws IOException {
            if (in == null)
                in = conn.getInputStream();
            super.close();
        }

        @Override
        public synchronized void mark(int readlimit) {
        }

        @Override
        public boolean markSupported() {
            return false;
        }

        @Override
        public int read() throws IOException {
            if (in == null)
                in = conn.getInputStream();
            return in.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (in == null)
                in = conn.getInputStream();
            return super.read(b, off, len);
        }

        @Override
        public int read(byte[] b) throws IOException {
            if (in == null)
                in = conn.getInputStream();
            return super.read(b);
        }

        @Override
        public synchronized void reset() throws IOException {
            if (in == null)
                in = conn.getInputStream();
            super.reset();
        }

        @Override
        public long skip(long n) throws IOException {
            if (in == null)
                in = conn.getInputStream();
            return super.skip(n);
        }

        /** URL connection providing the input stream. */
        private final URLConnection conn;
    }
}
