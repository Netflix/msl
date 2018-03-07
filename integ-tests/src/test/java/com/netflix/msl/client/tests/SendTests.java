/**
 * Copyright (c) 2017 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.client.tests;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.client.common.BaseTestClass;
import com.netflix.msl.client.configuration.ClientConfiguration;
import com.netflix.msl.client.configuration.ServerConfiguration;
import com.netflix.msl.client.configuration.msg.ClientMessageContext;
import com.netflix.msl.client.configuration.util.ClientMslContext;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationData;
import com.netflix.msl.io.Url;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageHeader;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.server.servlet.LogServlet;
import com.netflix.msl.util.MslStore;

/**
 * <p>Tests of the {@link MslControl} send methods.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SendTests extends BaseTestClass {
    /** Local entity identity. */
    private static final String ENTITY_IDENTITY = "send-test";
    
    /** Server path. */
    private static final String PATH = "/log";
    /** Network timeout in milliseconds. */
    private static final int TIMEOUT = 60000;
    
    @BeforeClass
    public void setup() throws IOException, URISyntaxException, MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException {
        super.loadProperties();
        serverConfig = new ServerConfiguration()
            .resetDefaultConfig()
            .setHost(getRemoteEntityUrl())
            .setPath(PATH);
        serverConfig.commitToServer();
        
        clientConfig = new ClientConfiguration()
            .setScheme("http")
            .setHost(getRemoteEntityUrl())
            .setPath(PATH)
            .setNumThreads(0)
            .setEntityAuthenticationScheme(EntityAuthenticationScheme.NONE);
        clientConfig.commitConfiguration();
        
        super.setServerMslCryptoContext();
    }
    
    @AfterMethod
    public void reset() {
        final MslStore store = clientConfig.getMslContext().getMslStore();
        store.clearCryptoContexts();
        store.clearUserIdTokens();
        store.clearServiceTokens();
    }
    
    /**
     * <p>Query the server for the reported string.</p>
     * 
     * @return the string returned by a report query.
     * @throws IOException if there is an error making the query.
     */
    public String report() throws IOException {
        // Prepare the request.
        final String uri = "http://" + getRemoteEntityUrl() + PATH + "?" + LogServlet.REPORT;
        final URL url = new URL(uri);
        final HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        conn.setRequestMethod("GET");
        
        // Read the response.
        final Reader in = new InputStreamReader(conn.getInputStream());
        final StringBuffer content = new StringBuffer();
        final char[] buffer = new char[16384];
        while (true) {
            final int count = in.read(buffer);
            if (count == -1) break;
            content.append(buffer, 0, count);
        }
        return content.toString();
    }
    
    @Test
    public void send() throws IOException, MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException, URISyntaxException {
        // Prepare.
        final String message = "fire-and-forget";
        final MslControl ctrl = clientConfig.getMslControl();
        final ClientMslContext ctx = clientConfig.getMslContext();
        ctx.setEntityAuthenticationData(new UnauthenticatedAuthenticationData(ENTITY_IDENTITY));
        clientConfig
            .setIsMessageEncrypted(false)
            .setIsIntegrityProtected(false)
            .clearKeyRequestData()
            .commitConfiguration();
        final ClientMessageContext msgCtx = clientConfig.getMessageContext();
        final Url remoteEntity = clientConfig.getRemoteEntity();
        
        // Send message.
        msgCtx.setBuffer(message.getBytes(MslConstants.DEFAULT_CHARSET));
        final Future<MessageOutputStream> future = ctrl.send(ctx, msgCtx, remoteEntity, TIMEOUT);
        MessageOutputStream mos = null;
        try {
            mos = future.get();
            Assert.assertNotNull(mos);
            final MessageHeader messageHeader = mos.getMessageHeader();
            Assert.assertNotNull(messageHeader);
            Assert.assertNull(messageHeader.getMasterToken());
        } catch (final ExecutionException | InterruptedException | CancellationException e) {
            e.printStackTrace(System.err);
            return;
        } finally {
            if (mos != null)
                try { mos.close(); } catch (final IOException e) {}
        }
        
        // Query receipt.
        final String report = report();
        Assert.assertEquals(report, message);
    }
    
    @Test
    public void handshakeSend() throws IOException, MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException, URISyntaxException {
        // Prepare.
        final String message = "handshake";
        final MslControl ctrl = clientConfig.getMslControl();
        final ClientMslContext ctx = clientConfig.getMslContext();
        ctx.setEntityAuthenticationData(new UnauthenticatedAuthenticationData(ENTITY_IDENTITY));
        clientConfig
            .setIsMessageEncrypted(true)
            .setIsIntegrityProtected(true)
            .setKeyRequestData(KeyExchangeScheme.ASYMMETRIC_WRAPPED)
            .commitConfiguration();
        final ClientMessageContext msgCtx = clientConfig.getMessageContext();
        final Url remoteEntity = clientConfig.getRemoteEntity();
        
        // Send message.
        msgCtx.setBuffer(message.getBytes(MslConstants.DEFAULT_CHARSET));
        final Future<MessageOutputStream> future = ctrl.send(ctx, msgCtx, remoteEntity, TIMEOUT);
        MessageOutputStream mos = null;
        try {
            mos = future.get();
            Assert.assertNotNull(mos);
            final MessageHeader messageHeader = mos.getMessageHeader();
            Assert.assertNotNull(messageHeader);
            Assert.assertNotNull(messageHeader.getMasterToken());
        } catch (final ExecutionException | InterruptedException | CancellationException e) {
            e.printStackTrace(System.err);
            return;
        } finally {
            if (mos != null)
                try { mos.close(); } catch (final IOException e) {}
        }
        
        // Query receipt.
        final String report = report();
        Assert.assertEquals(report, message);
    }

    /** Server configuration. */
    private ServerConfiguration serverConfig;
}
