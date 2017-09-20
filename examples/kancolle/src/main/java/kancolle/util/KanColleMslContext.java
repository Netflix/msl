/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
package kancolle.util;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import kancolle.KanColleConstants;
import kancolle.entityauth.KanColleEntityAuthenticationScheme;
import kancolle.entityauth.KanmusuAuthenticationFactory;
import kancolle.entityauth.KanmusuDatabase;
import kancolle.entityauth.NavalPortAuthenticationFactory;
import kancolle.entityauth.NavalPortDatabase;
import kancolle.keyx.KanColleDiffieHellmanParameters;
import kancolle.keyx.KanColleKeyxComparator;
import kancolle.tokens.KanColleTokenFactory;
import kancolle.userauth.KanColleUserAuthenticationScheme;
import kancolle.userauth.OfficerAuthenticationFactory;
import kancolle.userauth.OfficerDatabase;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.DefaultMslEncoderFactory;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.DiffieHellmanParameters;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.SimpleMslStore;

/**
 * <p>KanColle MSL context.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class KanColleMslContext extends MslContext {
    /**
     * Create a new KanColle MSL context.
     * 
     * @param ships Kanmusu ships database.
     * @param ports naval ports database.
     * @param officers officers database.
     */
    protected KanColleMslContext(final KanmusuDatabase ships, final NavalPortDatabase ports, final OfficerDatabase officers) {
        // Message capabilities.
        final Set<CompressionAlgorithm> compressionAlgos = new HashSet<CompressionAlgorithm>();
        compressionAlgos.add(CompressionAlgorithm.GZIP);
        final List<String> languages = Arrays.asList(KanColleConstants.en_US, KanColleConstants.ja_JP);
        final Set<MslEncoderFormat> encoderFormats = new HashSet<MslEncoderFormat>();
        encoderFormats.add(MslEncoderFormat.JSON);
        this.messageCaps = new MessageCapabilities(compressionAlgos, languages, encoderFormats);
        
        // Auxiliary authentication classes.
        final DiffieHellmanParameters params = new KanColleDiffieHellmanParameters();
        final KanColleAuthenticationUtils authutils = new KanColleAuthenticationUtils(ships, ports, officers);
        
        // Entity authentication factories.
        entityAuthFactories.put(KanColleEntityAuthenticationScheme.KANMUSU, new KanmusuAuthenticationFactory(ships));
        entityAuthFactories.put(KanColleEntityAuthenticationScheme.NAVAL_PORT, new NavalPortAuthenticationFactory(ports));
        
        // User authentication factories.
        userAuthFactories.put(KanColleUserAuthenticationScheme.OFFICER, new OfficerAuthenticationFactory(officers));
        
        // Key exchange factories.
        keyxFactories.add(new DiffieHellmanExchange(params, authutils));
        keyxFactories.add(new AsymmetricWrappedExchange(authutils));
        
        // Token factory.
        this.tokenFactory = new KanColleTokenFactory(authutils);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getTime()
     */
    @Override
    public long getTime() {
        return System.currentTimeMillis();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getRandom()
     */
    @Override
    public Random getRandom() {
        return new SecureRandom();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#isPeerToPeer()
     */
    @Override
    public boolean isPeerToPeer() {
        return false;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMessageCapabilities()
     */
    @Override
    public MessageCapabilities getMessageCapabilities() {
        return messageCaps;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationScheme(java.lang.String)
     */
    @Override
    public EntityAuthenticationScheme getEntityAuthenticationScheme(final String name) {
        return EntityAuthenticationScheme.getScheme(name);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationFactory(com.netflix.msl.entityauth.EntityAuthenticationScheme)
     */
    @Override
    public EntityAuthenticationFactory getEntityAuthenticationFactory(final EntityAuthenticationScheme scheme) {
        return entityAuthFactories.get(scheme);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getUserAuthenticationScheme(java.lang.String)
     */
    @Override
    public UserAuthenticationScheme getUserAuthenticationScheme(final String name) {
        return UserAuthenticationScheme.getScheme(name);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getUserAuthenticationFactory(com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public UserAuthenticationFactory getUserAuthenticationFactory(final UserAuthenticationScheme scheme) {
        return userAuthFactories.get(scheme);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getTokenFactory()
     */
    @Override
    public TokenFactory getTokenFactory() {
        return tokenFactory;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeScheme(java.lang.String)
     */
    @Override
    public KeyExchangeScheme getKeyExchangeScheme(final String name) {
        return KeyExchangeScheme.getScheme(name);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeFactory(com.netflix.msl.keyx.KeyExchangeScheme)
     */
    @Override
    public KeyExchangeFactory getKeyExchangeFactory(final KeyExchangeScheme scheme) {
        for (final KeyExchangeFactory factory : keyxFactories) {
            if (factory.getScheme().equals(scheme))
                return factory;
        }
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeFactories()
     */
    @Override
    public SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
        return Collections.unmodifiableSortedSet(keyxFactories);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslStore()
     */
    @Override
    public MslStore getMslStore() {
        return store;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslEncoderFactory()
     */
    @Override
    public MslEncoderFactory getMslEncoderFactory() {
        return encoderFactory;
    }

    /** Message capabilities. */
    private final MessageCapabilities messageCaps;
    /** Entity authentication factories by scheme. */
    private final Map<EntityAuthenticationScheme,EntityAuthenticationFactory> entityAuthFactories = new HashMap<EntityAuthenticationScheme,EntityAuthenticationFactory>();
    /** User authentication factories by scheme. */
    private final Map<UserAuthenticationScheme,UserAuthenticationFactory> userAuthFactories = new HashMap<UserAuthenticationScheme,UserAuthenticationFactory>();
    /** Key exchange factories. */
    private final SortedSet<KeyExchangeFactory> keyxFactories = new TreeSet<KeyExchangeFactory>(new KanColleKeyxComparator());
    /** Token factory. */
    private final TokenFactory tokenFactory;
    /** MSL store. */
    private final MslStore store = new SimpleMslStore();
    /** MSL encoder factory. */
    private final MslEncoderFactory encoderFactory = new DefaultMslEncoderFactory();
}
