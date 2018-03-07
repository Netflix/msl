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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.junit.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.client.common.BaseTestClass;
import com.netflix.msl.client.configuration.ClientConfiguration;
import com.netflix.msl.client.configuration.msg.ClientMessageContext;
import com.netflix.msl.client.configuration.util.ClientMslContext;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationData;
import com.netflix.msl.io.Url;
import com.netflix.msl.io.Url.Connection;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageInputStream;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MslControl;

/**
 * <p>Tests of the {@link MslControl} push methods.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class PushTests extends BaseTestClass {
    /** Local entity identity. */
    private static final String ENTITY_IDENTITY = "push-test";
    
    /** Network timeout in milliseconds. */
    private static final int TIMEOUT = 60000;
    
    public void init(final String path) throws URISyntaxException, IOException, MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException {
        clientConfig = new ClientConfiguration()
            .setScheme("http")
            .setHost(getRemoteEntityUrl())
            .setPath(path)
            .setNumThreads(0)
            .setEntityAuthenticationScheme(EntityAuthenticationScheme.NONE);
        clientConfig.commitConfiguration();
        
        super.setServerMslCryptoContext();
    }

    @BeforeClass
    public void setup() throws IOException {
        super.loadProperties();
    }
    
    @Test
    public void publicPush() throws MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException, URISyntaxException, IOException, InterruptedException, ExecutionException {
        // Initalize.
        init("/public-push");
        
        // Prepare.
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
        
        // Open connection.
        final Connection conn = remoteEntity.openConnection();
        final InputStream in = conn.getInputStream();
        final OutputStream out = conn.getOutputStream();
        
        // Send message.
        final byte[] output = new byte[16];
        ctx.getRandom().nextBytes(output);
        msgCtx.setBuffer(output);
        final Future<MessageOutputStream> send = ctrl.send(ctx, msgCtx, in, out, TIMEOUT);
        final MessageOutputStream mos = send.get();
        Assert.assertNotNull(mos);
        
        // Receive message.
        //
        // We expect to receive the output data back.
        final Future<MessageInputStream> receive = ctrl.receive(ctx, msgCtx, in, out, TIMEOUT);
        final MessageInputStream mis = receive.get();
        Assert.assertNotNull(mis);
        Assert.assertNotNull(mis.getMessageHeader());
        final ByteArrayOutputStream input = new ByteArrayOutputStream();
        do {
            final byte[] b = new byte[output.length];
            final int count = mis.read(b);
            if (count == -1) break;
            input.write(b, 0, count);
        } while (true);
        
        // Confirm data.
        Assert.assertArrayEquals(output, input.toByteArray());
    }
    
    @Test
    public void secretPush() throws MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException, URISyntaxException, IOException, InterruptedException, ExecutionException {
        // Initalize.
        init("/secret-push");
        
        // Prepare.
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
        
        // Open connection.
        final Connection conn = remoteEntity.openConnection();
        final InputStream in = conn.getInputStream();
        final OutputStream out = conn.getOutputStream();
        
        // Send message.
        final byte[] output = new byte[16];
        ctx.getRandom().nextBytes(output);
        msgCtx.setBuffer(output);
        final Future<MessageOutputStream> send = ctrl.send(ctx, msgCtx, in, out, TIMEOUT);
        final MessageOutputStream mos = send.get();
        Assert.assertNotNull(mos);
        
        // Receive message.
        //
        // We expect to receive an error indicating key exchange is required.
        final Future<MessageInputStream> receive = ctrl.receive(ctx, msgCtx, in, out, TIMEOUT);
        final MessageInputStream mis = receive.get();
        Assert.assertNotNull(mis);
        final ErrorHeader errorHeader = mis.getErrorHeader();
        Assert.assertNotNull(errorHeader);
        final ResponseCode responseCode = errorHeader.getErrorCode();
        Assert.assertEquals(MslConstants.ResponseCode.KEYX_REQUIRED, responseCode);
    }
    
    @Test
    public void multiPush() throws MslCryptoException, MslEncodingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, MslKeyExchangeException, URISyntaxException, IOException, InterruptedException, ExecutionException {
        // Initalize.
        init("/multi-push");
        
        // Prepare.
        final MslControl ctrl = clientConfig.getMslControl();
        ctrl.setFilterFactory(new ConsoleFilterStreamFactory());
        final ClientMslContext ctx = clientConfig.getMslContext();
        ctx.setEntityAuthenticationData(new UnauthenticatedAuthenticationData(ENTITY_IDENTITY));
        clientConfig
            .setIsMessageEncrypted(false)
            .setIsIntegrityProtected(false)
            .clearKeyRequestData()
            .commitConfiguration();
        final ClientMessageContext msgCtx = clientConfig.getMessageContext();
        final Url remoteEntity = clientConfig.getRemoteEntity();
        
        // Open connection.
        final Connection conn = remoteEntity.openConnection();
        final InputStream in = conn.getInputStream();
        final OutputStream out = conn.getOutputStream();
        
        // Send message.
        final byte[] output = new byte[16];
        ctx.getRandom().nextBytes(output);
        msgCtx.setBuffer(output);
        final Future<MessageOutputStream> send = ctrl.send(ctx, msgCtx, in, out, TIMEOUT);
        final MessageOutputStream mos = send.get();
        Assert.assertNotNull(mos);
        
        // Receive message.
        //
        // We expect to receive the output data back three times.
        for (int i = 0; i < 3; i++) {
            final Future<MessageInputStream> receive = ctrl.receive(ctx, msgCtx, in, out, TIMEOUT);
            final MessageInputStream mis = receive.get();
            Assert.assertNotNull(mis);
            Assert.assertNotNull(mis.getMessageHeader());
            final ByteArrayOutputStream input = new ByteArrayOutputStream();
            do {
                final byte[] b = new byte[output.length];
                final int count = mis.read(b);
                if (count == -1) break;
                input.write(b, 0, count);
            } while (true);
            
            // Confirm data.
            Assert.assertArrayEquals(output, input.toByteArray());
        }
    }
}
