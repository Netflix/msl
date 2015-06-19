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

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import com.netflix.msl.MslException;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.JsonWebEncryptionLadderExchange;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;

import mslcli.client.msg.ClientRequestMessageContext;
import mslcli.client.util.ClientMslContext;

import mslcli.common.msg.MessageConfig;
import mslcli.common.util.SharedUtil;

import static mslcli.common.Constants.*;

public final class Client {
    public Client(final String clientId, final MslControl mslCtrl) {
        if (clientId == null || clientId.trim().isEmpty()) {
            throw new IllegalArgumentException("Undefined Client Id");
        }
        if (mslCtrl == null) {
            throw new IllegalArgumentException("Undefined MSL COntrol");
        }

        // Set the MSL control.
        this.mslCtrl = mslCtrl;

        // Initialize MSL store.
        this.mslStore = SharedUtil.getClientMslStore();

        // Create the pre-shared key store.
        final PresharedKeyStore presharedKeyStore = SharedUtil.getClientPresharedKeyStore();

        // Create the RSA key store
        final RsaStore rsaStore = SharedUtil.getClientRsaStore();

        // Create the email/password store.
        final EmailPasswordStore emailPasswordStore = SharedUtil.getClientEmailPasswordStore();

        // Set up the MSL context
        this.mslCtx = new ClientMslContext(clientId, presharedKeyStore, rsaStore, emailPasswordStore, mslStore);

        // Initialize UserAuthenticationData
        this.userAuthData = new EmailPasswordAuthenticationData(CLIENT_USER_EMAIL, CLIENT_USER_PASSWORD);

        // initialize key request data
        this.keyRequestDataSet = new HashSet<KeyRequestData>();
    }

    public byte[] sendRequest(final byte[] request, final MessageConfig cfg, final URL remoteUrl)
        throws ExecutionException, IOException, InterruptedException, MslException
    {

        final MessageContext msgCtx = new ClientRequestMessageContext(
            mslCtx,
            cfg.isEncrypted,
            cfg.isIntegrityProtected,
            cfg.isNonReplayable,
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

        final ErrorHeader errHeader = ch.input.getErrorHeader();
        if (errHeader == null) {
            MasterToken mt = mslStore.getMasterToken();
            if (mt != latestMasterToken) {
                if (mt != null) {
                    System.out.println(String.format("\n\nINFO: New Master Token: serial_num %d, seq_num %d\n", mt.getSerialNumber(), mt.getSequenceNumber()));
                    latestMasterToken = mt;
                } else {
                    System.out.println("\n\nINFO: Master Tokens Purged from MSL Store\n");
                }
            }
            return SharedUtil.readIntoArray(ch.input);
        } else {
            if (errHeader.getErrorMessage() != null) {
                System.err.println(String.format("ERROR: error_code %d, error_msg \"%s\"", errHeader.getErrorCode().intValue(), errHeader.getErrorMessage()));
            } else {
                System.err.println(String.format("ERROR: %s" + errHeader.toJSONString()));
            }
            return null;
        }
    }

    public void setKeyRequestData(final String kxType, final String mechanism) throws MslException, IOException {
        System.out.println("resetting MSL store ...");
        mslStore.clearCryptoContexts();
        keyRequestDataSet.clear();
        if (KX_DH.equals(kxType)) {
            final KeyPair dhKeyPair = SharedUtil.generateDiffieHellmanKeys(DEFAULT_DH_PARAMS_ID);
            keyRequestDataSet.add(new DiffieHellmanExchange.RequestData(DEFAULT_DH_PARAMS_ID, ((DHPublicKey)dhKeyPair.getPublic()).getY(), (DHPrivateKey)dhKeyPair.getPrivate()));
        } else if (KX_SWE.equals(kxType)) {
            keyRequestDataSet.add(new SymmetricWrappedExchange.RequestData(SymmetricWrappedExchange.KeyId.PSK));
        } else if (KX_AWE.equals(kxType)) {
            if (mechanism == null) {
                throw new IllegalArgumentException("Missing Key Wrapping Mechanism for Asymmetric Wrapped Key Exchange");
            }
            final AsymmetricWrappedExchange.RequestData.Mechanism m = Enum.valueOf(AsymmetricWrappedExchange.RequestData.Mechanism.class, mechanism);
            if (aweKeyPair == null) {
               aweKeyPair = SharedUtil.generateAsymmetricWrappedExchangeKeyPair();
            }
            keyRequestDataSet.add(new AsymmetricWrappedExchange.RequestData(DEFAULT_AWE_KEY_PAIR_ID, m, aweKeyPair.getPublic(), aweKeyPair.getPrivate()));
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

    /** Cached RSA Key Pair for asymmetric key wrap key exchange to avoid expensive key pair generation.
     * This is an optimization specific to this application, to avoid annoying delays in generating
     * 4096-bit RSA key pairs. Real-life implementations should not re-use key wrapping keys
     * too many times.
     */
    private KeyPair aweKeyPair = null;

    /** keep track of the latest master token in MSL store */
    private MasterToken latestMasterToken = null;
}
