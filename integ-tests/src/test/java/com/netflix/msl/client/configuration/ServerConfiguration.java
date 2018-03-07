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
package com.netflix.msl.client.configuration;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.netflix.msl.client.configuration.tokens.TokenFactoryType;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * User: skommidi
 * Date: 7/25/14
 */
public class ServerConfiguration {
    private static class NameValuePair {
        public NameValuePair(final String name, final String value) {
            try {
                this.name = URLEncoder.encode(name, "UTF-8");
                this.value = URLEncoder.encode(value, "UTF-8");
            } catch (final UnsupportedEncodingException e) {
                throw new RuntimeException("UTF-8 encoding not supported.", e);
            }
        }
        
        private final String name;
        private final String value;
    }
    
    private final String scheme = "http";
    private String path;
    private String host;
    private int numThreads;
    private EntityAuthenticationScheme entityAuthScheme;
    private TokenFactoryType tokenFactoryType;
    private long initialSequenceNum;
    private boolean isMessageEncrypted;
    private boolean isIntegrityProtected;
    private boolean isNullCryptoContext;
    private boolean setConsoleFilterStreamFactory;
    private List<EntityAuthenticationScheme> unSupportedEntityAuthFactories;
    private List<UserAuthenticationScheme> unSupportedUserAuthFactories;
    private List<KeyExchangeScheme> unSupportedKeyxFactories;
    private final List<NameValuePair> nvps;

    private static final String NUM_THREADS = "numthreads";
    private static final String ENTITY_AUTH_SCHEME = "entityauthscheme";
    private static final String TOKEN_FACTORY_TYPE = "tokenfactorytype";
    private static final String INITIAL_SEQUENCE_NUM = "initialseqnum";
    private static final String ENCRYPTED = "encrypted";
    private static final String NULL_CRYPTO_CONTEXT = "nullCryptoContext";
    private static final String CONSOLE_FILTER_STREAM_FACTORY = "consoleFilterStreamFactory";
    private static final String UNSUPPORTED_ENTITY_SCHEMES = "unsupentityauthfact";
    private static final String UNSUPPORTED_USER_SCHEMES = "unsupuserauthfact";
    private static final String UNSUPPORTED_KEY_EXCHANGE_SCHEMES = "unsupkeyexfact";
    private static final String INTEGRITY_PROTECTED = "intProtected";


    public ServerConfiguration() {
        nvps = new ArrayList<NameValuePair>();
    }

    public ServerConfiguration resetDefaultConfig() {
        this.numThreads = 0;
        this.entityAuthScheme = EntityAuthenticationScheme.NONE;
        this.tokenFactoryType = TokenFactoryType.NOT_ACCEPT_NON_REPLAYABLE_ID;
        this.initialSequenceNum = 8L;
        this.isMessageEncrypted = true;
        this.isIntegrityProtected = true;
        this.unSupportedEntityAuthFactories = null;
        this.unSupportedUserAuthFactories = null;
        this.unSupportedKeyxFactories = null;
        this.isNullCryptoContext = false;
        this.setConsoleFilterStreamFactory = false;
        this.setNameValuePairs();
        return this;
    }

    private void setNameValuePairs() {
        nvps.add(new NameValuePair(NUM_THREADS, String.valueOf(numThreads)));
        nvps.add(new NameValuePair(ENTITY_AUTH_SCHEME, String.valueOf(entityAuthScheme)));
        nvps.add(new NameValuePair(TOKEN_FACTORY_TYPE, String.valueOf(tokenFactoryType)));
        nvps.add(new NameValuePair(INITIAL_SEQUENCE_NUM, String.valueOf(initialSequenceNum)));
        nvps.add(new NameValuePair(ENCRYPTED, String.valueOf(isMessageEncrypted)));
        nvps.add(new NameValuePair(INTEGRITY_PROTECTED, String.valueOf(isIntegrityProtected)));
        nvps.add(new NameValuePair(NULL_CRYPTO_CONTEXT, String.valueOf(isNullCryptoContext)));
        nvps.add(new NameValuePair(CONSOLE_FILTER_STREAM_FACTORY, String.valueOf(setConsoleFilterStreamFactory)));
        if(unSupportedEntityAuthFactories!=null) {
            for(final EntityAuthenticationScheme scheme : unSupportedEntityAuthFactories) {
                nvps.add(new NameValuePair(UNSUPPORTED_ENTITY_SCHEMES, String.valueOf(scheme)));
            }
        }
        if(unSupportedUserAuthFactories!=null) {
            for(final UserAuthenticationScheme scheme : unSupportedUserAuthFactories) {
                nvps.add(new NameValuePair(UNSUPPORTED_USER_SCHEMES, String.valueOf(scheme)));
            }
        }
        if(unSupportedKeyxFactories!=null) {
            for(final KeyExchangeScheme scheme : unSupportedKeyxFactories) {
                nvps.add(new NameValuePair(UNSUPPORTED_KEY_EXCHANGE_SCHEMES, String.valueOf(scheme)));
            }
        }
    }

    public ServerConfiguration isMessageEncrypted(final boolean isMessageEncrypted) {
        this.isMessageEncrypted = isMessageEncrypted;
        setParameter(ENCRYPTED, String.valueOf(this.isMessageEncrypted));
        return this;
    }

    public ServerConfiguration isIntegrityProtected(final boolean isIntegrityProtected) {
        this.isIntegrityProtected = isIntegrityProtected;
        setParameter(INTEGRITY_PROTECTED, String.valueOf(this.isIntegrityProtected));
        return this;
    }

    public ServerConfiguration setHost(final String host) {
        this.host = host;
        return this;
    }

    public ServerConfiguration setPath(final String path) {
        this.path = path;
        return this;
    }

    public ServerConfiguration setIsNullCryptoContext(final boolean isNullCryptoContext) {
        this.isNullCryptoContext = isNullCryptoContext;
        setParameter(NULL_CRYPTO_CONTEXT, String.valueOf(this.isNullCryptoContext));
        return this;
    }

    public ServerConfiguration setInitialSequenceNumber(final long initialSequenceNumber) {
        this.initialSequenceNum = initialSequenceNumber;
        setParameter(INITIAL_SEQUENCE_NUM, String.valueOf(this.initialSequenceNum));
        return this;
    }

    public ServerConfiguration setSetConsoleFilterStreamFactory(final boolean setConsoleFilterStreamFactory) {
        this.setConsoleFilterStreamFactory = setConsoleFilterStreamFactory;
        setParameter(CONSOLE_FILTER_STREAM_FACTORY, String.valueOf(this.setConsoleFilterStreamFactory));
        return this;
    }

    public ServerConfiguration setUnsupportedEntityAuthenticationSchemes(final List<EntityAuthenticationScheme> unSupportedEntityAuthFactories) {
        this.unSupportedEntityAuthFactories = unSupportedEntityAuthFactories;
        clearParameter(UNSUPPORTED_ENTITY_SCHEMES);
        if(this.unSupportedEntityAuthFactories!=null) {
            for(final EntityAuthenticationScheme scheme : this.unSupportedEntityAuthFactories) {
                nvps.add(new NameValuePair(UNSUPPORTED_ENTITY_SCHEMES, String.valueOf(scheme)));
            }
        }
        return this;
    }

    public ServerConfiguration setUnsupportedUserAuthenticationSchemes(final List<UserAuthenticationScheme> unSupportedUserAuthFactories) {
        this.unSupportedUserAuthFactories = unSupportedUserAuthFactories;
        clearParameter(UNSUPPORTED_USER_SCHEMES);
        if(this.unSupportedUserAuthFactories!=null) {
            for(final UserAuthenticationScheme scheme : this.unSupportedUserAuthFactories) {
                nvps.add(new NameValuePair(UNSUPPORTED_USER_SCHEMES, String.valueOf(scheme)));
            }
        }
        return this;
    }

    public ServerConfiguration setUnsupportedKeyExchangeSchemes(final List<KeyExchangeScheme> unSupportedKeyxFactories) {
        this.unSupportedKeyxFactories = unSupportedKeyxFactories;
        clearParameter(UNSUPPORTED_KEY_EXCHANGE_SCHEMES);
        if(this.unSupportedKeyxFactories != null) {
            for(final KeyExchangeScheme scheme : this.unSupportedKeyxFactories) {
                nvps.add(new NameValuePair(UNSUPPORTED_KEY_EXCHANGE_SCHEMES, String.valueOf(scheme)));
            }
        }
        return this;
    }

    public ServerConfiguration clearParameters() {
        nvps.clear();
        return this;
    }

    public ServerConfiguration clearParameter(final String name) {
        if (!nvps.isEmpty()) {
            for (final Iterator<NameValuePair> it = nvps.iterator(); it.hasNext(); ) {
                final NameValuePair nvp = it.next();
                if (nvp.name.equals(name)) {
                    it.remove();
                }
            }
        }

        return this;
    }

    public ServerConfiguration setParameter(final String name, final String value) {
        clearParameter(name);
        nvps.add(new NameValuePair(name, value));
        return this;
    }

    public void commitToServer() throws URISyntaxException, IOException {
        final StringBuilder urlBuilder = new StringBuilder(scheme + "://" + host + path + "?");
        for (final NameValuePair pair : nvps)
            urlBuilder.append(pair.name + "=" + pair.value + "&");
        final URL url = new URL(urlBuilder.toString());
        
        final HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        conn.setRequestMethod("GET");
        conn.getResponseCode();
    }
}