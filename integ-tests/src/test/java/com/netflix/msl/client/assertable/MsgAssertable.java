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
package com.netflix.msl.client.assertable;

import com.netflix.msl.MslConstants;
import com.netflix.msl.client.configuration.ClientConfiguration;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageHeader;
import com.netflix.msl.msg.MessageInputStream;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * User: skommidi
 * Date: 7/25/14
 */
public class MsgAssertable {

    private MessageInputStream msg;
    private MessageHeader msg_hdr;
    private ErrorHeader err_hdr;
    private boolean booleanExpectation;
    byte[] buffer = new byte[5];


    public MsgAssertable(MessageInputStream message) {
        this.msg = message;
    }

    public MsgAssertable shouldBe() {
        this.booleanExpectation = true;
        return this;
    }

    public MsgAssertable shouldHave() {
        this.booleanExpectation = true;
        return this;
    }

    public MsgAssertable shouldNotBe() {
        this.booleanExpectation = false;
        return this;
    }

    public MsgAssertable validFirstEntityAuthPSKMsg() {
        Date now = new Date();

        try {
            msg_hdr = msg.getMessageHeader();
            err_hdr = msg.getErrorHeader();
            assertNull(err_hdr);
            assertNotNull(msg_hdr);
            //First response for PSK contain key exchange data and master token
            assertNotNull(msg.getKeyExchangeCryptoContext());
            assertNotNull(msg.getPayloadCryptoContext());
            //MasterToken is not in the message header its in the keyResponseData
            assertNull(msg_hdr.getMasterToken());
            assertNotNull(msg_hdr.getKeyResponseData().getMasterToken());
            assertNotNull(msg_hdr.getKeyResponseData().getMasterToken().getRenewalWindow());
            assertNotNull(msg_hdr.getKeyResponseData().getMasterToken().getSequenceNumber());
            assertFalse(msg_hdr.getKeyResponseData().getMasterToken().isDecrypted());
            assertFalse(msg_hdr.getKeyResponseData().getMasterToken().isVerified());
            assertFalse(msg_hdr.getKeyResponseData().getMasterToken().isRenewable(now));
            assertTrue(msg_hdr.getKeyRequestData().isEmpty());
            assertNull(msg_hdr.getUserAuthenticationData());
            assertNotNull(msg_hdr.getUserIdToken());
            assertFalse(msg_hdr.getUserIdToken().isDecrypted());
            assertFalse(msg_hdr.getUserIdToken().isVerified());
            assertFalse(msg_hdr.getUserIdToken().isExpired(now));
            assertEquals(msg_hdr.getUserIdToken().getMasterTokenSerialNumber(), msg_hdr.getKeyResponseData().getMasterToken().getSerialNumber());
            assertNotNull(msg_hdr.getUserIdToken().getRenewalWindow());
            assertFalse(msg_hdr.getUserIdToken().isRenewable(now));
        } catch(AssertionError e) {
            if(this.booleanExpectation) {
                throw e;
            }
        }
        return this;
    }

    public MsgAssertable validFirstMsg(boolean user_auth_data_null) {
        Date now = new Date();

        try {
            msg_hdr = msg.getMessageHeader();
            err_hdr = msg.getErrorHeader();
            assertNull(err_hdr);
            assertNotNull(msg_hdr);

            //First response for RSA does not contain key exchange data and master token
            assertNull(msg.getKeyExchangeCryptoContext());
            assertNotNull(msg.getPayloadCryptoContext());

            //MasterToken is in the message header its not in the keyResponseData, this is after handshake
            assertNotNull(msg_hdr.getMasterToken());
            assertNull(msg_hdr.getKeyResponseData());
            assertTrue(msg_hdr.getKeyRequestData().isEmpty());
            assertNull(msg_hdr.getUserAuthenticationData());

            //If userauthdata is null there is no userIdToken in response.
            if(!user_auth_data_null) {
                assertNotNull(msg_hdr.getUserIdToken());
                assertFalse(msg_hdr.getUserIdToken().isDecrypted());
                assertFalse(msg_hdr.getUserIdToken().isVerified());
                assertFalse(msg_hdr.getUserIdToken().isExpired(now));
                assertEquals(msg_hdr.getUserIdToken().getMasterTokenSerialNumber(), msg_hdr.getMasterToken().getSerialNumber());
                assertNotNull(msg_hdr.getUserIdToken().getRenewalWindow());
                assertFalse(msg_hdr.getUserIdToken().isRenewable(now));
            }

        } catch(AssertionError e) {
            if(this.booleanExpectation) {
                throw e;
            }
        }
        return this;
    }

    public MsgAssertable validBuffer() throws IOException {
        do {
            final int bytesRead = msg.read(buffer);
            if (bytesRead == -1) break;
        } while (true);
        if(Arrays.equals(buffer, ClientConfiguration.serverError.getBytes(MslConstants.DEFAULT_CHARSET))) {
            fail("Buffer mis-match on server");
        }
        assertEquals(this.booleanExpectation, Arrays.equals(buffer, ClientConfiguration.input.getBytes(MslConstants.DEFAULT_CHARSET)));

        return this;
    }

    public MsgAssertable validateSecondMsg() {
        validateSecondMsg(false);
        return this;
    }

    public MsgAssertable validateSecondMsg(boolean user_auth_data_null) {
        try {
            msg_hdr = msg.getMessageHeader();
            assertNull(msg.getErrorHeader());
            assertNotNull(msg_hdr);
            //Once MasterToken is received there should be no keyResponseData
            assertNull(msg.getKeyExchangeCryptoContext());
            assertNotNull(msg.getPayloadCryptoContext());
            assertNotNull(msg_hdr.getMasterToken());
            assertTrue(msg_hdr.getKeyRequestData().isEmpty());
            assertNull(msg_hdr.getUserAuthenticationData());

            //If userauthdata is null there is no userIdToken in response.
            if(!user_auth_data_null) {
                assertNotNull(msg_hdr.getUserIdToken());
            }

        } catch (AssertionError e) {
            if(this.booleanExpectation) {
                throw e;
            }
        }

        return this;
    }

    public MsgAssertable validFirstEntityAuthRSAMsg() {
        validFirstMsg(false);
        return this;
    }

    public MsgAssertable validFirstEntityAuthECCMsg() {
        validFirstMsg(false);
        return this;
    }

    public MsgAssertable validFirstEntityAuthX509Msg() {
        validFirstMsg(false);
        return this;
    }

    public MsgAssertable validFirstEntityAuthNONEMsg() {
        validFirstMsg(false);
        return this;
    }

    public MsgAssertable validFirstEntityAuthNONEMsg(boolean user_auth_data_null) {
        validFirstMsg(user_auth_data_null);
        return this;
    }
}
