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
package kancolle.keyx;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.keyx.DiffieHellmanExchange.RequestData;
import com.netflix.msl.keyx.DiffieHellmanParameters;

/**
 * <p>Shared Diffie-Hellman instance to minimize key exchange overhead. New key
 * request data should be generated after every successful key exchange.</p>
 * 
 * <p>This class is thread-safe.</p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class DiffieHellmanManager {
    /**
     * @param params Diffie-Hellman parameters.
     * @param paramId the ID of the Diffie-Hellman parameters to use.
     */
    public DiffieHellmanManager(DiffieHellmanParameters params, final String paramId) {
        this.params = params;
        this.paramId = paramId;
    }
    
    /**
     * <p>Return the current Diffie-Hellman key exchange request data. If no
     * request data exists new data is generated.</p>
     * 
     * @return the Diffie-Hellman request data.
     * @throws MslKeyExchangeException if there is an error accessing the
     *         Diffie-Hellman parameters.
     * @see #clearRequest()
     */
    public synchronized RequestData getRequestData() throws MslKeyExchangeException {
        // Generate new request data if necessary.
        if (request == null) {
            final DHParameterSpec paramSpec = params.getParameterSpec(paramId);
            final KeyPairGenerator generator;
            try {
                generator = KeyPairGenerator.getInstance("DH");
                generator.initialize(paramSpec);
            } catch (final NoSuchAlgorithmException e) {
                throw new MslInternalException("Diffie-Hellman algorithm not found.", e);
            } catch (final InvalidAlgorithmParameterException e) {
                throw new MslInternalException("Diffie-Hellman algorithm parameters rejected by Diffie-Hellman key agreement.", e);
            }
            final KeyPair requestKeyPair = generator.generateKeyPair();
            final BigInteger publicKey = ((DHPublicKey)requestKeyPair.getPublic()).getY();
            final DHPrivateKey privateKey = (DHPrivateKey)requestKeyPair.getPrivate();
            request = new RequestData(KanColleDiffieHellmanParameters.PARAM_ID, publicKey, privateKey);
        }
        return request;
    }
    
    /**
     * <p>Clear the current Diffie-Hellman key exchange request data. The next
     * call to {@link #getRequestData()} will generate new request data.</p>
     * 
     * @see #getRequestData()
     */
    public synchronized void clearRequest() {
        request = null;
    }
    
    /** The Diffie-Hellman parameters. */
    private final DiffieHellmanParameters params;
    /** The Diffie-Hellman parameters ID to use. */
    private final String paramId;
    
    /** The current request data. */
    private RequestData request;
}
