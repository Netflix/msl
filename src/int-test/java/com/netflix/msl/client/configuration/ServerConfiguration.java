package com.netflix.msl.client.configuration;

import com.netflix.msl.client.configuration.tokens.TokenFactoryType;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * User: skommidi
 * Date: 7/25/14
 */
public class ServerConfiguration {



    private URIBuilder uriBuilder;
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
    private List<NameValuePair> nvps;

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
        uriBuilder = new URIBuilder()
                .setScheme("http");
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
        nvps.add(new BasicNameValuePair(NUM_THREADS, String.valueOf(numThreads)));
        nvps.add(new BasicNameValuePair(ENTITY_AUTH_SCHEME, String.valueOf(entityAuthScheme)));
        nvps.add(new BasicNameValuePair(TOKEN_FACTORY_TYPE, String.valueOf(tokenFactoryType)));
        nvps.add(new BasicNameValuePair(INITIAL_SEQUENCE_NUM, String.valueOf(initialSequenceNum)));
        nvps.add(new BasicNameValuePair(ENCRYPTED, String.valueOf(isMessageEncrypted)));
        nvps.add(new BasicNameValuePair(INTEGRITY_PROTECTED, String.valueOf(isIntegrityProtected)));
        nvps.add(new BasicNameValuePair(NULL_CRYPTO_CONTEXT, String.valueOf(isNullCryptoContext)));
        nvps.add(new BasicNameValuePair(CONSOLE_FILTER_STREAM_FACTORY, String.valueOf(setConsoleFilterStreamFactory)));
        if(unSupportedEntityAuthFactories!=null) {
            for(EntityAuthenticationScheme scheme : unSupportedEntityAuthFactories) {
                nvps.add(new BasicNameValuePair(UNSUPPORTED_ENTITY_SCHEMES, String.valueOf(scheme)));
            }
        }
        if(unSupportedUserAuthFactories!=null) {
            for(UserAuthenticationScheme scheme : unSupportedUserAuthFactories) {
                nvps.add(new BasicNameValuePair(UNSUPPORTED_USER_SCHEMES, String.valueOf(scheme)));
            }
        }
        if(unSupportedKeyxFactories!=null) {
            for(KeyExchangeScheme scheme : unSupportedKeyxFactories) {
                nvps.add(new BasicNameValuePair(UNSUPPORTED_KEY_EXCHANGE_SCHEMES, String.valueOf(scheme)));
            }
        }
    }

    public ServerConfiguration isMessageEncrypted(boolean isMessageEncrypted) {
        this.isMessageEncrypted = isMessageEncrypted;
        setParameter(ENCRYPTED, String.valueOf(this.isMessageEncrypted));
        return this;
    }

    public ServerConfiguration isIntegrityProtected(boolean isIntegrityProtected) {
        this.isIntegrityProtected = isIntegrityProtected;
        setParameter(INTEGRITY_PROTECTED, String.valueOf(this.isIntegrityProtected));
        return this;
    }

    public ServerConfiguration setHost(String host) {
        this.host = host;
        uriBuilder.setHost(this.host);
        return this;
    }

    public ServerConfiguration setPath(String path) {
        this.path = path;
        uriBuilder.setPath(this.path);
        return this;
    }

    public ServerConfiguration setIsNullCryptoContext(boolean isNullCryptoContext) {
        this.isNullCryptoContext = isNullCryptoContext;
        setParameter(NULL_CRYPTO_CONTEXT, String.valueOf(this.isNullCryptoContext));
        return this;
    }

    public ServerConfiguration setInitialSequenceNumber(long initialSequenceNumber) {
        this.initialSequenceNum = initialSequenceNumber;
        setParameter(INITIAL_SEQUENCE_NUM, String.valueOf(this.initialSequenceNum));
        return this;
    }

    public ServerConfiguration setSetConsoleFilterStreamFactory(boolean setConsoleFilterStreamFactory) {
        this.setConsoleFilterStreamFactory = setConsoleFilterStreamFactory;
        setParameter(CONSOLE_FILTER_STREAM_FACTORY, String.valueOf(this.setConsoleFilterStreamFactory));
        return this;
    }

    public ServerConfiguration setUnsupportedEntityAuthenticationSchemes(List<EntityAuthenticationScheme> unSupportedEntityAuthFactories) {
        this.unSupportedEntityAuthFactories = unSupportedEntityAuthFactories;
        clearParameter(UNSUPPORTED_ENTITY_SCHEMES);
        if(this.unSupportedEntityAuthFactories!=null) {
            for(EntityAuthenticationScheme scheme : this.unSupportedEntityAuthFactories) {
                nvps.add(new BasicNameValuePair(UNSUPPORTED_ENTITY_SCHEMES, String.valueOf(scheme)));
            }
        }
        return this;
    }

    public ServerConfiguration setUnsupportedUserAuthenticationSchemes(List<UserAuthenticationScheme> unSupportedUserAuthFactories) {
        this.unSupportedUserAuthFactories = unSupportedUserAuthFactories;
        clearParameter(UNSUPPORTED_USER_SCHEMES);
        if(this.unSupportedUserAuthFactories!=null) {
            for(UserAuthenticationScheme scheme : this.unSupportedUserAuthFactories) {
                nvps.add(new BasicNameValuePair(UNSUPPORTED_USER_SCHEMES, String.valueOf(scheme)));
            }
        }
        return this;
    }

    public ServerConfiguration setUnsupportedKeyExchangeSchemes(List<KeyExchangeScheme> unSupportedKeyxFactories) {
        this.unSupportedKeyxFactories = unSupportedKeyxFactories;
        clearParameter(UNSUPPORTED_KEY_EXCHANGE_SCHEMES);
        if(this.unSupportedKeyxFactories != null) {
            for(KeyExchangeScheme scheme : this.unSupportedKeyxFactories) {
                nvps.add(new BasicNameValuePair(UNSUPPORTED_KEY_EXCHANGE_SCHEMES, String.valueOf(scheme)));
            }
        }
        return this;
    }

    public ServerConfiguration clearParameters() {
        nvps.clear();
        return this;
    }

    public ServerConfiguration clearParameter(String name) {
        if (!nvps.isEmpty()) {
            for (final Iterator<NameValuePair> it = nvps.iterator(); it.hasNext(); ) {
                final NameValuePair nvp = it.next();
                if (nvp.getName().equals(name)) {
                    it.remove();
                }
            }
        }

        return this;
    }

    public ServerConfiguration setParameter(String name, String value) {
        clearParameter(name);
        nvps.add(new BasicNameValuePair(name, value));
        return this;
    }

    public void commitToServer() throws URISyntaxException, IOException {
        CloseableHttpClient client = HttpClients.createDefault();
        URI uri = uriBuilder.setParameters(nvps).build();
        HttpGet get = new HttpGet(uri);
        CloseableHttpResponse response = client.execute(get);

        try {
            System.out.println(response.getStatusLine());
            HttpEntity entity = response.getEntity();
            System.out.println(EntityUtils.toString(entity));
        } finally {
            response.close();
        }
    }
}