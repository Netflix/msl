/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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
package oneshot;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.SortedSet;
import java.util.TreeSet;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.crypto.ClientMslCryptoContext;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.RsaAuthenticationFactory;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationFactory;
import com.netflix.msl.io.DefaultMslEncoderFactory;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.tokens.ClientTokenFactory;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.NullAuthenticationUtils;
import com.netflix.msl.util.SimpleMslStore;

/**
 * <p>Simple MSL context for the oneshot example.</p>
 * 
 * <p>This configuration uses the unauthenticated entity authentication scheme
 * and the asymmetric wrapped key exchange scheme. It does not support secure
 * MSL token issuance or remote user authentication.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class OneshotMslContext extends MslContext {
	/** Random. */
	private static final Random random = new SecureRandom();
	/** MSL crypto context. */
	private static final ICryptoContext mslCryptoContext = new ClientMslCryptoContext();
	/** Token factory. */
	private static final TokenFactory tokenFactory = new ClientTokenFactory();
	/** Encoder factory. */
	private static final MslEncoderFactory encoderFactory = new DefaultMslEncoderFactory();
	
	/**
	 * <p>Create a new oneshot MSL context.</p>
	 * 
	 * @param identity local entity identity.
	 * @param rsaStore RSA key store for remote entity authentication.
	 */
	public OneshotMslContext(final String identity, final RsaStore rsaStore) {
		// Create local entity authentication data.
		this.entityAuthData = new UnauthenticatedAuthenticationData(identity);
		
		// Populate entity authentication factories, including remote entity
		// authentication.
		final AuthenticationUtils authutils = new NullAuthenticationUtils();
		this.entityAuthFactories = new HashMap<EntityAuthenticationScheme,EntityAuthenticationFactory>();
		this.entityAuthFactories.put(EntityAuthenticationScheme.NONE, new UnauthenticatedAuthenticationFactory(authutils));
		this.entityAuthFactories.put(EntityAuthenticationScheme.RSA, new RsaAuthenticationFactory(rsaStore, authutils));
		
		// Populate key exchange factories.
		this.keyxFactories = new HashMap<KeyExchangeScheme,KeyExchangeFactory>();
		this.keyxFactories.put(KeyExchangeScheme.ASYMMETRIC_WRAPPED, new AsymmetricWrappedExchange(authutils));
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
		return random;
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
		return null;
	}

	/* (non-Javadoc)
	 * @see com.netflix.msl.util.MslContext#getEntityAuthenticationData(com.netflix.msl.util.MslContext.ReauthCode)
	 */
	@Override
	public EntityAuthenticationData getEntityAuthenticationData(final ReauthCode reauthCode) {
		return entityAuthData;
	}

    /* (non-Javadoc)
	 * @see com.netflix.msl.util.MslContext#getMslCryptoContext()
	 */
	@Override
	public ICryptoContext getMslCryptoContext() throws MslCryptoException {
		return mslCryptoContext;
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
		return null;
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
		return keyxFactories.get(scheme);
	}

	/* (non-Javadoc)
	 * @see com.netflix.msl.util.MslContext#getKeyExchangeFactories()
	 */
	@Override
	public SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
		return new TreeSet<KeyExchangeFactory>(keyxFactories.values());
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
	
	/** Entity authentication data. */
	private final EntityAuthenticationData entityAuthData;
	/** Entity authentication factories. */
	private final Map<EntityAuthenticationScheme,EntityAuthenticationFactory> entityAuthFactories;
	/** Key exchange factories. */
	private final Map<KeyExchangeScheme,KeyExchangeFactory> keyxFactories;
	/** MSL store. */
	private final MslStore store = new SimpleMslStore();
}
