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
package burp.msl.msg;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.DiffieHellmanParameters;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.MockDiffieHellmanParameters;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MessageDebugContext;
import com.netflix.msl.msg.MessageOutputStream;
import com.netflix.msl.msg.MessageServiceTokenBuilder;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationData;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * <p>This message context does not specify any security requirements and
 * imposes no unnecessary message properties (e.g. no user, no modifications
 * to service tokens).</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class WiretapMessageContext implements MessageContext {
    private static final String DH_PARAMETERS_ID = "1";
    private static final String RSA_KEYPAIR_ID = "rsaKeypairId";

    /**
     * <p>Create a new wiretap message context with the provided message debug
     * context. The debug context is used to capture received MSL message
     * headers which can then be inspected.</p>
     * 
     * @param dbgCtx the message debug context.
     */
    public WiretapMessageContext(final MessageDebugContext dbgCtx) throws MslKeyExchangeException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        this.dbgCtx = dbgCtx;

        keyRequestData = new HashSet<KeyRequestData>();
        {
            final DiffieHellmanParameters params = MockDiffieHellmanParameters.getDefaultParameters();
            final DHParameterSpec paramSpec = params.getParameterSpec(MockDiffieHellmanParameters.DEFAULT_ID);
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
            generator.initialize(paramSpec);
            final KeyPair requestKeyPair = generator.generateKeyPair();
            final BigInteger publicKey = ((DHPublicKey)requestKeyPair.getPublic()).getY();
            final DHPrivateKey privateKey = (DHPrivateKey)requestKeyPair.getPrivate();
            keyRequestData.add(new DiffieHellmanExchange.RequestData(DH_PARAMETERS_ID, publicKey, privateKey));
        }
        {
            final KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
            final KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
            final PublicKey publicKey = rsaKeyPair.getPublic();
            final PrivateKey privateKey = rsaKeyPair.getPrivate();
            keyRequestData.add(new AsymmetricWrappedExchange.RequestData(RSA_KEYPAIR_ID, AsymmetricWrappedExchange.RequestData.Mechanism.RSA, publicKey, privateKey));
        }
        {
            keyRequestData.add(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK));
        }
    }
    
    @Override
    public Map<String, ICryptoContext> getCryptoContexts() {
        return Collections.emptyMap();
    }

    @Override
    public String getRemoteEntityIdentity() {
        return null;
    }

    @Override
    public boolean isEncrypted() {
        return false;
    }

    @Override
    public boolean isIntegrityProtected() {
        return false;
    }

    @Override
    public boolean isNonReplayable() {
        return false;
    }

    @Override
    public boolean isRequestingTokens() {
        return false;
    }

    @Override
    public String getUserId() {
        return null;
    }

    @Override
    public UserAuthenticationData getUserAuthData(final ReauthCode reauthCode, final boolean renewable, final boolean required) {
        return null;
    }

    @Override
    public MslUser getUser() {
        return null;
    }

    @Override
    public Set<KeyRequestData> getKeyRequestData() {
        return Collections.unmodifiableSet(keyRequestData);
    }

    @Override
    public void updateServiceTokens(final MessageServiceTokenBuilder builder, final boolean handshake) {
    }

    @Override
    public void write(final MessageOutputStream output) throws IOException {
        output.close();
    }

    @Override
    public MessageDebugContext getDebugContext() {
        return dbgCtx;
    }
    
    /** Message debug context. */
    private final MessageDebugContext dbgCtx;
    private final HashSet<KeyRequestData> keyRequestData;
}
