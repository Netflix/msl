/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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
package burp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Set;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageHeader;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.MslTestUtils;

import burp.msl.WiretapException;
import burp.msl.WiretapModule;
import burp.msl.msg.CaptureMessageDebugContext;
import burp.msl.msg.WiretapMessageContext;
import burp.msl.msg.WiretapMessageInputStream;
import burp.msl.util.WiretapMslContext;

/**
 * User: skommidi
 * Date: 9/25/14
 */
public class MSLHttpListener implements IHttpListener {

    private static final String KEY_ENTITY_AUTHENTICATION_DATA = "entityauthdata";
    private static final String KEY_MASTER_TOKEN = "mastertoken";
    private static final String KEY_HEADERDATA = "headerdata";
    private static final String KEY_SIGNATURE = "signature";
    private static final String KEY_MESSAGE_ID = "messageid";
    private static final String KEY_RENEWABLE = "renewable";
    private static final String KEY_CAPABILITIES = "capabilities";
    private static final String KEY_KEY_REQUEST_DATA = "keyrequestdata";
    private static final String KEY_KEY_RESPONSE_DATA = "keyresponsedata";
    private static final String KEY_USER_AUTHENTICATION_DATA = "userauthdata";
    private static final String KEY_USER_ID_TOKEN = "useridtoken";
    private static final String KEY_SERVICE_TOKENS = "servicetokens";
    private static final String KEY_NON_REPLAYABLE_ID = "nonreplayableid";
    private static final String KEY_HANDSHAKE = "handshake";
    private static final String KEY_PAYLOAD = "payload";
    private static final String KEY_ERRORDATA = "errordata";
    private static final String KEY_ERROR_CODE = "errorcode";
    private static final String KEY_INTERNAL_CODE = "internalcode";
    private static final String KEY_ERROR_MESSAGE = "errormsg";
    private static final String KEY_USER_MESSAGE = "usermsg";
    private static final String KEY_DATA = "data";
    private static final String KEY_TOKENDATA = "tokendata";
    private static final String KEY_RENEWAL_WINDOW = "renewalwindow";
    private static final String KEY_EXPIRATION = "expiration";
    private static final String KEY_SEQUENCE_NUMBER = "sequencenumber";
    private static final String KEY_SERIAL_NUMBER = "serialnumber";
    private static final String KEY_SESSIONDATA = "sessiondata";
    private static final String KEY_MASTER_TOKEN_SERIAL_NUMBER = "mtserialnumber";
    private static final String KEY_USERDATA = "userdata";

    public MSLHttpListener() throws MslCryptoException {
        this(null, null);
    }

    public MSLHttpListener(final IBurpExtenderCallbacks callbacks, final IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;

        // obtain our output streams
        if(this.callbacks != null && this.helpers != null) {
            stdout = new PrintWriter(callbacks.getStdout(), true);
        } else {
            stdout = new PrintWriter(System.out);
        }

        try {
            initializeMsl();
        } catch (final MslCryptoException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private void initializeMsl() throws MslCryptoException {
        final WiretapModule module = new WiretapModule();
        final Set<EntityAuthenticationFactory> entityAuthFactories = module.provideEntityAuthFactories();
        final Set<UserAuthenticationFactory> userAuthFactories = module.provideUserAuthFactories();
        this.ctx = new WiretapMslContext(entityAuthFactories, userAuthFactories);
        
        // Change the entity auth data to your usecase
        ctx.setEntityAuthenticationData(EntityAuthenticationScheme.PSK);

        final CaptureMessageDebugContext dbgCtx = new CaptureMessageDebugContext(true, true);
        try {
            msgCtx = new WiretapMessageContext(dbgCtx);
        } catch (final MslKeyExchangeException e) {
            throw new RuntimeException(e.getMessage());
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        } catch (final InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    public void processHttpMessage(final int toolFlag, final boolean messageIsRequest, final IHttpRequestResponse messageInfo) throws WiretapException {

        if(messageIsRequest) {
            // Get MSL Message
            final String body = getBody(messageIsRequest, messageInfo);
            if(body == null)
                return;

            stdout.println();
            stdout.println("Request:");
//            stdout.println(body);
//            stdout.println("Starting MSL Processing");

            processMslMessage(body);

        } else {
            // Get MSL Message
            final String body = getBody(messageIsRequest, messageInfo);
            if(body == null)
                return;

            stdout.println();
            stdout.println("Response:");
//            stdout.println(body);
//            stdout.println("Starting MSL Processing");

            processMslMessage(body);
        }


    }

    protected String getBody(final boolean messageIsRequest, final IHttpRequestResponse messageInfo) {

        String body = null;
        if(messageIsRequest) {
            final IRequestInfo requestInfo = this.helpers.analyzeRequest(messageInfo);

            // Ignore HTTP Get Requests.
            if(requestInfo.getMethod().equalsIgnoreCase("GET")) {
                ignoreNextResponse = true;
                return body;
            }

            ignoreNextResponse = false;

            // Extracting body part of request message, this is actual MSL message.
            final String request = new String(messageInfo.getRequest());
            body = request.substring(requestInfo.getBodyOffset());

        } else {
            if(ignoreNextResponse) {
                return body;
            }

            final IResponseInfo responseInfo = this.helpers.analyzeResponse(messageInfo.getResponse());

            // Extracting body part of request message, this is actual MSL message.
            final String response = new String(messageInfo.getResponse());
            body = response.substring(responseInfo.getBodyOffset());
        }

        return body;
    }

    protected String getBody(final byte[] message) {

        String body = null;

        final IRequestInfo requestInfo = this.helpers.analyzeRequest(null, message);

        // Extracting body part of request message, this is actual MSL message.
        final String request = new String(message);
        body = request.substring(requestInfo.getBodyOffset());

        return body;
    }

    protected String processMslMessage(final String body) throws WiretapException {
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final MslEncoderFormat format = encoder.getPreferredFormat(null);
        final StringBuilder retData = new StringBuilder("");

        WiretapMessageInputStream mis;
        try {
            final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(body.getBytes());
            mis = new WiretapMessageInputStream(this.ctx, byteArrayInputStream, this.msgCtx.getKeyRequestData(), this.msgCtx.getCryptoContexts());
        } catch (final IOException e) {
            throw new WiretapException(e.getMessage(), e);
        } catch (final MslException e) {
            throw new WiretapException(e.getMessage(), e);
        }

        // Check if instance of ErrorHeader
        final ErrorHeader errorHeader = mis.getErrorHeader();
        try {
            if (errorHeader != null) {
                // Create error headerdata MSL Object
                final MslObject errHeaderMo = encoder.createObject();
    
                // if entity auth data is present add that to the JSON object
                if(errorHeader.getEntityAuthenticationData() != null) {
                    try {
                        errHeaderMo.put(KEY_ENTITY_AUTHENTICATION_DATA, errorHeader.getEntityAuthenticationData());
                    } catch (final IllegalArgumentException e) {
                        throw new WiretapException(e.getMessage(), e);
                    }
                }
    
                final MslObject errordataMo = encoder.createObject();
                try {
                    errordataMo.put(KEY_MESSAGE_ID, errorHeader.getMessageId());
                    errordataMo.put(KEY_ERROR_CODE, errorHeader.getErrorCode().intValue());
                    errordataMo.put(KEY_INTERNAL_CODE, errorHeader.getInternalCode());
                    errordataMo.put(KEY_ERROR_MESSAGE, errorHeader.getErrorMessage());
                    errordataMo.put(KEY_USER_MESSAGE, errorHeader.getUserMessage());
    
                    // Add headerdata in clear
                    errHeaderMo.put(KEY_ERRORDATA, errordataMo);
                    stdout.println(errHeaderMo); retData.append(errHeaderMo.toString() + "\n");
                    stdout.println(); retData.append("\n");
                } catch (final IllegalArgumentException e) {
                    throw new WiretapException(e.getMessage(), e);
                }
    
                return retData.toString();
            }
        } finally {
            try { mis.close(); } catch (final IOException e) {}
        }
        
        try {
            final MessageHeader messageHeader = mis.getMessageHeader();

            // Create message headerdata MSL object
            final MslObject msgHeaderMo = encoder.createObject();

            // if entity auth data is present add that to the MSL object
            if(messageHeader.getEntityAuthenticationData() != null) {
                try {
                    msgHeaderMo.put(KEY_ENTITY_AUTHENTICATION_DATA, messageHeader.getEntityAuthenticationData());
                } catch (final IllegalArgumentException e) {
                    throw new WiretapException(e.getMessage(), e);
                }
            }

            MasterToken masterToken = null;

            // if master token is present add that to the JSON object
            if(messageHeader.getMasterToken() != null) {
                masterToken = messageHeader.getMasterToken();
                try {
                    final MslObject parsedMasterTokenMo = parseMasterToken(masterToken);
                    msgHeaderMo.put(KEY_MASTER_TOKEN, parsedMasterTokenMo);
                } catch (final IllegalArgumentException e) {
                    throw new WiretapException(e.getMessage(), e);
                } catch (final MslException e) {
                    throw new WiretapException(e.getMessage(), e);
                }
            }

            final MslObject headerdataMo = encoder.createObject();
            try {
                headerdataMo.put(KEY_MESSAGE_ID, messageHeader.getMessageId());
                headerdataMo.put(KEY_NON_REPLAYABLE_ID, messageHeader.getNonReplayableId());
                headerdataMo.put(KEY_RENEWABLE, messageHeader.isRenewable());
                headerdataMo.put(KEY_HANDSHAKE, messageHeader.isHandshake());
                headerdataMo.put(KEY_CAPABILITIES, messageHeader.getMessageCapabilities());
                if(!messageHeader.getKeyRequestData().isEmpty())
                    headerdataMo.put(KEY_KEY_REQUEST_DATA, MslEncoderUtils.createArray(ctx, format, messageHeader.getKeyRequestData()));
                if(messageHeader.getKeyResponseData() != null) {
                    final MslObject keyResponseDataMo = MslTestUtils.toMslObject(encoder, messageHeader.getKeyResponseData());
                    if(messageHeader.getKeyResponseData().getMasterToken() != null) {
                        masterToken = messageHeader.getKeyResponseData().getMasterToken();
                        keyResponseDataMo.remove(KEY_MASTER_TOKEN);
                        final MslObject parsedMasterTokenMo = parseMasterToken(messageHeader.getKeyResponseData().getMasterToken());
                        keyResponseDataMo.put(KEY_MASTER_TOKEN, parsedMasterTokenMo);
                    }
                    headerdataMo.put(KEY_KEY_RESPONSE_DATA, keyResponseDataMo);
                }
                if(messageHeader.getUserAuthenticationData() != null)
                    headerdataMo.put(KEY_USER_AUTHENTICATION_DATA, messageHeader.getUserAuthenticationData());
                if(messageHeader.getUserIdToken() != null) {
                    headerdataMo.put(KEY_USER_ID_TOKEN, parseUserIdToken(messageHeader.getUserIdToken(), masterToken));
                }
                if(!messageHeader.getServiceTokens().isEmpty())
                    headerdataMo.put(KEY_SERVICE_TOKENS, MslEncoderUtils.createArray(ctx, format, messageHeader.getServiceTokens()));

                // Add headerdata in clear
                msgHeaderMo.put(KEY_HEADERDATA, headerdataMo);
                stdout.println(msgHeaderMo); retData.append(msgHeaderMo.toString() + "\n");
            } catch (final MslEncoderException e) {
                throw new WiretapException(e.getMessage(), e);
            } catch (final MslException e) {
                throw new WiretapException(e.getMessage(), e);
            }

            try {
                MslObject payloadTokenMo;
                while((payloadTokenMo = mis.nextPayload()) != null) {
                    final String data = Base64.encode(payloadTokenMo.getBytes(KEY_DATA));
                    payloadTokenMo.remove(KEY_DATA);
                    payloadTokenMo.put(KEY_DATA, data);
    
                    final MslObject payloadMo = encoder.createObject();
                    payloadMo.put(KEY_PAYLOAD, payloadTokenMo);
                    stdout.println(payloadMo); retData.append(payloadMo.toString() + "\n");
                }
                stdout.println(); retData.append("\n");
            } catch (final Exception e) {
                throw new WiretapException(e.getMessage(), e);
            }
            stdout.flush();
        } finally {
            try { mis.close(); } catch (final IOException e) {}
        }

        return retData.toString();
    }

    private MslObject parseUserIdToken(final UserIdToken userIdToken, final MasterToken masterToken) throws MslException {
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();

        byte[] tokendata;
        // Verify the JSON representation.
        boolean verified = false;
        try {
            final MslObject userIdTokenMo = MslTestUtils.toMslObject(encoder, userIdToken);
            tokendata = userIdTokenMo.getBytes(KEY_TOKENDATA);
            if (tokendata.length == 0)
                throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_MISSING, "useridtoken " + userIdTokenMo.toString()).setMasterToken(masterToken);
            final byte[] signature = userIdTokenMo.getBytes(KEY_SIGNATURE);
            verified = cryptoContext.verify(tokendata, signature, encoder);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "useridtoken " + userIdToken, e).setMasterToken(masterToken);
        }

        // Pull the token data.
        final MslObject tokenDataMo;
        byte[] userdata;
        long mtSerialNumber;
        try {
            tokenDataMo = encoder.parseObject(tokendata);
            final long renewalWindow = tokenDataMo.getLong(KEY_RENEWAL_WINDOW);
            final long expiration = tokenDataMo.getLong(KEY_EXPIRATION);
            if (expiration < renewalWindow)
                throw new MslException(MslError.USERIDTOKEN_EXPIRES_BEFORE_RENEWAL, "usertokendata " + tokenDataMo).setMasterToken(masterToken);
            mtSerialNumber = tokenDataMo.getLong(KEY_MASTER_TOKEN_SERIAL_NUMBER);
            if (mtSerialNumber < 0 || mtSerialNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokenDataMo).setMasterToken(masterToken);
            final long serialNumber = tokenDataMo.getLong(KEY_SERIAL_NUMBER);
            if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.USERIDTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "usertokendata " + tokenDataMo).setMasterToken(masterToken);
            final byte[] ciphertext = tokenDataMo.getBytes(KEY_USERDATA);
            if (ciphertext.length == 0)
                throw new MslException(MslError.USERIDTOKEN_USERDATA_MISSING, tokenDataMo.getString(KEY_USERDATA)).setMasterToken(masterToken);
            userdata = (verified) ? cryptoContext.decrypt(ciphertext, encoder) : null;
            tokenDataMo.remove(KEY_USERDATA);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.USERIDTOKEN_TOKENDATA_PARSE_ERROR, "usertokendata " + Base64.encode(tokendata), e).setMasterToken(masterToken);
        } catch (final MslCryptoException e) {
            e.setMasterToken(masterToken);
            throw e;
        }

        // Pull the user data.
        if (userdata != null) {
            try {
                final MslObject userDataMo = encoder.parseObject(userdata);
                tokenDataMo.put(KEY_USERDATA, userDataMo);
            } catch (final MslEncoderException e) {
                throw new MslEncodingException(MslError.USERIDTOKEN_USERDATA_PARSE_ERROR, "userdata " + Base64.encode(userdata), e).setMasterToken(masterToken);
            }
        }

        // Verify serial numbers.
        if (masterToken == null || mtSerialNumber != masterToken.getSerialNumber())
            throw new MslException(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH, "uit mtserialnumber " + mtSerialNumber + "; mt " + masterToken).setMasterToken(masterToken);

        return tokenDataMo;
    }

    private MslObject parseMasterToken(final MasterToken masterToken) throws MslException {
        final ICryptoContext cryptoContext = ctx.getMslCryptoContext();
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();

        byte[] tokendata;
        // Verify the JSON representation.
        boolean verified = false;
        try {
            final MslObject masterTokenMo = MslTestUtils.toMslObject(encoder, masterToken);
            tokendata = masterTokenMo.getBytes(KEY_TOKENDATA);
            if (tokendata.length == 0)
                throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_MISSING, "mastertoken " + masterTokenMo.toString());
            final byte[] signature = masterTokenMo.getBytes(KEY_SIGNATURE);
            verified = cryptoContext.verify(tokendata, signature, encoder);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "mastertoken " + masterToken, e);
        }

        // Pull the token data.
        final MslObject tokenDataMo;
        final byte[] sessiondata;
        try {
            tokenDataMo = encoder.parseObject(tokendata);
            final long renewalWindow = tokenDataMo.getLong(KEY_RENEWAL_WINDOW);
            final long expiration = tokenDataMo.getLong(KEY_EXPIRATION);
            if (expiration < renewalWindow)
                throw new MslException(MslError.MASTERTOKEN_EXPIRES_BEFORE_RENEWAL, "mastertokendata " + tokenDataMo);
            final long sequenceNumber = tokenDataMo.getLong(KEY_SEQUENCE_NUMBER);
            if (sequenceNumber < 0 || sequenceNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.MASTERTOKEN_SEQUENCE_NUMBER_OUT_OF_RANGE, "mastertokendata " + tokenDataMo);
            final long serialNumber = tokenDataMo.getLong(KEY_SERIAL_NUMBER);
            if (serialNumber < 0 || serialNumber > MslConstants.MAX_LONG_VALUE)
                throw new MslException(MslError.MASTERTOKEN_SERIAL_NUMBER_OUT_OF_RANGE, "mastertokendata " + tokenDataMo);
            final byte[] ciphertext;
            try {
                ciphertext = tokenDataMo.getBytes(KEY_SESSIONDATA);
            } catch (final IllegalArgumentException e) {
                throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_INVALID, tokenDataMo.getString(KEY_SESSIONDATA));
            }
            if (ciphertext == null || ciphertext.length == 0)
                throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_MISSING, tokenDataMo.getString(KEY_SESSIONDATA));
            sessiondata = (verified) ? cryptoContext.decrypt(ciphertext, encoder) : null;
            tokenDataMo.remove(KEY_SESSIONDATA);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MASTERTOKEN_TOKENDATA_PARSE_ERROR, "mastertokendata " + Base64.encode(tokendata), e);
        }

        // Pull the session data.
        if (sessiondata != null) {
            try {
                final MslObject sessionDataMo = encoder.parseObject(sessiondata);
                tokenDataMo.put(KEY_SESSIONDATA, sessionDataMo);
            } catch (final MslEncoderException e) {
                throw new MslEncodingException(MslError.MASTERTOKEN_SESSIONDATA_PARSE_ERROR, "sessiondata " + Base64.encode(sessiondata), e);
            }
        }

        return tokenDataMo;
    }

    private final PrintWriter stdout;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private WiretapMessageContext msgCtx;
    private WiretapMslContext ctx = null;
    private boolean ignoreNextResponse = false;
}
