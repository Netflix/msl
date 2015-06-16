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

package mslcli.client;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import javax.crypto.interfaces.DHPrivateKey;

import com.netflix.msl.MslException;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.JsonWebEncryptionLadderExchange;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;

import mslcli.client.msg.ClientRequestMessageContext;
import mslcli.client.util.ClientMslContext;

import mslcli.common.util.SharedUtil;

import static mslcli.common.Constants.*;

public final class Client {
    // Add BouncyCastle provider.
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String KX_DH   = "dh" ; // Diffie-Hellman             Key Exchange
    private static final String KX_SWE  = "sw" ; // Symmetric  Wrapped         Key Exchange
    private static final String KX_AWE  = "aw" ; // Asymmetric Wrapped         Key Exchange
    private static final String KX_JWEL = "jwe"; // JSON Web Encryption Ladder Key Exchange
    private static final String KX_JWKL = "jwk"; // JSON Web Key        Ladder Key Exchange

    private static final Set<String> supportedKxTypes = Collections.unmodifiableSet(
        new HashSet<String>(Arrays.asList(KX_DH, KX_SWE, KX_AWE, KX_JWEL, KX_JWKL)));

    // Asymmetric Wrapped Key Exchange Mechanisms
    private static final Set<String> supportedAsymmetricWrappedExchangeMechanisms = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
                                                                            AsymmetricWrappedExchange.RequestData.Mechanism.JWE_RSA.toString(),
                                                                            AsymmetricWrappedExchange.RequestData.Mechanism.JWEJS_RSA.toString(),
                                                                            AsymmetricWrappedExchange.RequestData.Mechanism.JWK_RSA.toString(),
                                                                            AsymmetricWrappedExchange.RequestData.Mechanism.JWK_RSAES.toString())));
                                                                           

    private static final String QUIT = "q";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Specify remote URL");
            System.exit(1);
        }
        final URL remoteUrl = new URL(args[0]);
        final Client client = new Client();

        String kxType;
        while (!QUIT.equalsIgnoreCase(kxType = SharedUtil.readInput(String.format("KeyExchange(\"%s\" to exit) %s", QUIT, supportedKxTypes.toString())))) {
            if (supportedKxTypes.contains(kxType)) {
                client.setKeyRequestData(kxType);
            } else {
                continue;
            }
                
            String msg;
            while (!QUIT.equalsIgnoreCase(msg = SharedUtil.readInput(String.format("Message(\"%s\" to switch key exchange)", QUIT)))) {
                final byte[] response = client.sendRequest(msg.getBytes(), remoteUrl);
                System.out.println("\nResponse: " + new String(response));
            }
        }
    }

    public Client() {
        // Create the MSL control.
        //
        // Since this is an example process all requests on the calling thread.
        this.mslCtrl = new MslControl(0);
        this.mslCtrl.setFilterFactory(new ConsoleFilterStreamFactory());

        // Initialize MSL store.
        this.mslStore = SharedUtil.getClientMslStore();

        // Create the pre-shared key store.
        final PresharedKeyStore presharedKeyStore = SharedUtil.getPresharedKeyStore();

        // Create the RSA key store
        final RsaStore rsaStore = SharedUtil.getRsaStore();

        // Create the email/password store.
        final EmailPasswordStore emailPasswordStore = SharedUtil.getEmailPasswordStore();

        // Set up the MSL context
        this.mslCtx = new ClientMslContext(CLIENT_ID, presharedKeyStore, rsaStore, emailPasswordStore, mslStore);

        // Initialize UserAuthenticationData
        this.userAuthData = new EmailPasswordAuthenticationData(CLIENT_USER_EMAIL, CLIENT_USER_PASSWORD);

        // initialize key request data
        this.keyRequestDataSet = new HashSet<KeyRequestData>();
    }

    public byte[] sendRequest(byte[] request, URL remoteUrl) throws ExecutionException, IOException, InterruptedException, MslException {
        final boolean isEncrypted = true;
        final boolean isIntegrityProtected = true;
        final boolean isNonReplayable = false;

        final MessageContext msgCtx = new ClientRequestMessageContext(
            mslCtx,
            isEncrypted,
            isIntegrityProtected,
            isNonReplayable,
            CLIENT_USER_ID,
            userAuthData,
            keyRequestDataSet,
            request
            );

        final Future<MslChannel> f = mslCtrl.request(mslCtx, msgCtx, remoteUrl, TIMEOUT_MS);
        final MslChannel ch;
        ch = f.get();
        if (ch == null)
            return null;

        return SharedUtil.readIntoArray(ch.input);
    }

    private void setKeyRequestData(final String kxType) throws MslException, IOException {
        System.out.println("resetting MSL store ...");
        mslStore.clearCryptoContexts();
        keyRequestDataSet.clear();
        if (KX_DH.equals(kxType)) {
            SharedUtil.DiffieHellmanPair dhPair = SharedUtil.generateDiffieHellmanKeys(DEFAULT_DH_PARAMS_ID);
            keyRequestDataSet.add(new DiffieHellmanExchange.RequestData(DEFAULT_DH_PARAMS_ID, dhPair.getPublic().getY(), dhPair.getPrivate()));
        } else if (KX_SWE.equals(kxType)) {
            keyRequestDataSet.add(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK));
        } else if (KX_AWE.equals(kxType)) {
            String mechanism;
            do {
                mechanism = SharedUtil.readInput(String.format("Mechanism%s", supportedAsymmetricWrappedExchangeMechanisms.toString()));
            } while (!supportedAsymmetricWrappedExchangeMechanisms.contains(mechanism));
            final AsymmetricWrappedExchange.RequestData.Mechanism m = Enum.valueOf(AsymmetricWrappedExchange.RequestData.Mechanism.class, mechanism);
            final KeyPair keyPair = SharedUtil.generateAsymmetricWrappedExchangeKeyPair();
            keyRequestDataSet.add(new AsymmetricWrappedExchange.RequestData(DEFAULT_AWE_KEY_PAIR_ID, m, keyPair.getPublic(), keyPair.getPrivate()));
            
        } else if (KX_JWEL.equals(kxType)) {
            final JsonWebEncryptionLadderExchange.Mechanism m = JsonWebEncryptionLadderExchange.Mechanism.PSK;
            final byte[] wrapdata = null;
            keyRequestDataSet.add(new JsonWebEncryptionLadderExchange.RequestData(m, wrapdata));
        } else if (KX_JWKL.equals(kxType)) {
            final JsonWebKeyLadderExchange.Mechanism m = JsonWebKeyLadderExchange.Mechanism.PSK;
            final byte[] wrapdata = null;
            keyRequestDataSet.add(new JsonWebKeyLadderExchange.RequestData(m, wrapdata));
        } else {
            throw new IllegalArgumentException("Unsupported Key Exchange Type " + kxType);
        }
    }

    /** MSL context */
    private final MslContext mslCtx;
    /** MSL control */
    private final MslControl mslCtrl;
    /** User Authentication Data */
    private final UserAuthenticationData userAuthData;
    /** key request data set chosen by MslControl in the order of preference */
    private final Set<KeyRequestData> keyRequestDataSet;
    /** MSL store storing master tokens with associated crypto context, user id tokens, and service tokens */
    private final MslStore mslStore;
}
