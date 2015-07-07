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
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.JsonWebEncryptionLadderExchange;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.msg.ErrorHeader;
import com.netflix.msl.msg.MessageContext;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.msg.MslControl.MslChannel;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.userauth.EmailPasswordStore;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;

import mslcli.client.msg.ClientRequestMessageContext;
import mslcli.client.msg.MessageConfig;
import mslcli.client.util.UserAuthenticationDataHandle;

import mslcli.client.util.ClientMslContext;

import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.SharedUtil;

import static mslcli.client.CmdArguments.*;

/**
 * MSL Client class.
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class Client {

    private static final int TIMEOUT_MS = 120 * 1000;

    /** default asymmetrik key wrap exchange key pair id - the value should not matter */
    private static final String DEFAULT_AWE_KEY_PAIR_ID = "default_awe_key_id";

    /**
     * Data object encapsulating payload and/or error header from the server
     */
    public static final class Response {
        private Response(final byte[] payload, final ErrorHeader errHeader) {
            this.payload = payload;
            this.errHeader = errHeader;
        }
        public byte[] getPayload() {
            return payload;
        }
        public ErrorHeader getErrorHeader() {
            return errHeader;
        }
        private final byte[] payload;
        private final ErrorHeader errHeader;
    }
        
    /**
     * @param appCtx application context
     * @param clientId client entity identity
     */
    public Client(final AppContext appCtx, final String clientId) throws ConfigurationException {
        if (appCtx == null) {
            throw new IllegalArgumentException("NULL app context");
        }
        if (clientId == null || clientId.trim().isEmpty()) {
            throw new IllegalArgumentException("Undefined Client Id");
        }

        // Initialize app context.
        this.appCtx = appCtx;

        // Set client ID
        this.clientId = clientId;

        // Initialize MSL store.
        this.mslStore = appCtx.getMslStore();

        // Set up the MSL context
        this.mslCtx = new ClientMslContext(appCtx, clientId);

        // Set up the MSL Control
        this.mslCtrl = appCtx.getMslControl();

        // initialize key request data
        this.keyRequestDataSet = new HashSet<KeyRequestData>();
    }

    /**
     * Send single request.
     * @param request message payload to send
     * @param cfg message security policies
     * @param remoteUrl target URL for sending message
     * @return response encapsulating payload and/or error header
     */
    public Response sendRequest(final byte[] request, final MessageConfig cfg, final URL remoteUrl)
        throws ExecutionException, IOException, InterruptedException, MslException
    {
        if (userAuthenticationDataHandle == null) {
            throw new IllegalStateException("Uninitialized UserAuthenticationDataHandle");
        }

        final MessageContext msgCtx = new ClientRequestMessageContext(
            cfg.isEncrypted,
            cfg.isIntegrityProtected,
            cfg.isNonReplayable,
            cfg.userId,
            userAuthenticationDataHandle,
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
            return new Response(SharedUtil.readIntoArray(ch.input), null);
        } else {
            return new Response(null, errHeader);
        }
    }

    /**
     * Set key request data for specific key request scheme and (if applicable) mechanism.
     * @param kxsName key exchange scheme name
     * @param kxmName key exchange mechanism name
     */
    public void setKeyRequestData(final String kxsName, final String kxmName)
        throws ConfigurationException, IllegalCmdArgumentException, MslKeyExchangeException
    {
        if (kxsName == null || kxsName.trim().isEmpty()) {
            throw new IllegalArgumentException("NULL Key Exchange Type");
        }
        final KeyExchangeScheme kxScheme = KeyExchangeScheme.getScheme(kxsName.trim());
        if (kxScheme == null) {
            throw new IllegalCmdArgumentException(String.format("Invalid Key Exchange Type %s: valid %s", kxsName.trim(), KeyExchangeScheme.values()));
        }
        keyRequestDataSet.clear();

        if (kxScheme == KeyExchangeScheme.DIFFIE_HELLMAN) {
            if (kxmName != null) {
                throw new IllegalCmdArgumentException("No Key Wrapping Mechanism Needed for Key Exchange " + kxScheme.name());
            }
            final String diffieHellmanParametersId = appCtx.getDiffieHellmanParametersId(clientId);
            final KeyPair dhKeyPair = appCtx.generateDiffieHellmanKeys(diffieHellmanParametersId);
            keyRequestDataSet.add(new DiffieHellmanExchange.RequestData(diffieHellmanParametersId,
                ((DHPublicKey)dhKeyPair.getPublic()).getY(), (DHPrivateKey)dhKeyPair.getPrivate()));
        } else if (kxScheme == KeyExchangeScheme.SYMMETRIC_WRAPPED) {
            final SymmetricWrappedExchange.KeyId keyId = getKeyExchangeMechanism(
                SymmetricWrappedExchange.KeyId.class, kxScheme, kxmName);
            keyRequestDataSet.add(new SymmetricWrappedExchange.RequestData(keyId));
        } else if (kxScheme == KeyExchangeScheme.ASYMMETRIC_WRAPPED) {
            final AsymmetricWrappedExchange.RequestData.Mechanism m = getKeyExchangeMechanism(
                AsymmetricWrappedExchange.RequestData.Mechanism.class, kxScheme, kxmName);
            if (aweKeyPair == null) {
               aweKeyPair = appCtx.generateAsymmetricWrappedExchangeKeyPair();
            }
            keyRequestDataSet.add(new AsymmetricWrappedExchange.RequestData(DEFAULT_AWE_KEY_PAIR_ID, m, aweKeyPair.getPublic(), aweKeyPair.getPrivate()));
        } else if (kxScheme == KeyExchangeScheme.JWE_LADDER) {
            final JsonWebEncryptionLadderExchange.Mechanism m = getKeyExchangeMechanism(
                JsonWebEncryptionLadderExchange.Mechanism.class, kxScheme, kxmName);
            final byte[] wrapdata = (m == JsonWebEncryptionLadderExchange.Mechanism.WRAP) ?
                appCtx.getWrapCryptoContextRepository().getLastWrapdata() : null;
            keyRequestDataSet.add(new JsonWebEncryptionLadderExchange.RequestData(m, wrapdata));
        } else if (kxScheme == KeyExchangeScheme.JWK_LADDER) {
            final JsonWebKeyLadderExchange.Mechanism m = getKeyExchangeMechanism(
                JsonWebKeyLadderExchange.Mechanism.class, kxScheme, kxmName);
            final byte[] wrapdata = (m == JsonWebKeyLadderExchange.Mechanism.WRAP) ?
                appCtx.getWrapCryptoContextRepository().getLastWrapdata() : null;
            keyRequestDataSet.add(new JsonWebKeyLadderExchange.RequestData(m, wrapdata));
        } else {
            throw new IllegalCmdArgumentException("Unsupported Key Exchange Scheme " + kxScheme);
        }
    }

    private static <T extends Enum<T>> T getKeyExchangeMechanism(final Class<T> clazz, final KeyExchangeScheme keyExchangeScheme, final String kxmName)
         throws IllegalCmdArgumentException
    {
        final List<T> values = Arrays.asList(clazz.getEnumConstants());
        if (kxmName == null || kxmName.trim().isEmpty()) {
            throw new IllegalCmdArgumentException(String.format("Missing Key Exchange Mechanism for %s: Valid %s",
                keyExchangeScheme.name(), values));
        }
        try {
            return Enum.valueOf(clazz, kxmName.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalCmdArgumentException(String.format("Illegal Key Exchange %s for %s, Valid %s",
                keyExchangeScheme.name(), kxmName.trim(), values));
        }
    }

    /**
     * Set user authentication data handle
     * @param userAuthenticationDataHandle user authentication data handle callback
     */
    public void setUserAuthenticationDataHandle(final UserAuthenticationDataHandle userAuthenticationDataHandle) {
        if (userAuthenticationDataHandle == null) {
            throw new IllegalArgumentException("NULL UserAuthenticationDataHandle");
        }
        this.userAuthenticationDataHandle = userAuthenticationDataHandle;
    }

    /**
     * @return MSL Store
     */
    public MslStore getMslStore() {
        return mslStore;
    }

    /** App context */
    private final AppContext appCtx;

    /** Client Entity ID */
    private final String clientId;

    /** MSL context */
    private final MslContext mslCtx;

    /** MSL control */
    private final MslControl mslCtrl;

    /** User Authentication Data */
    private UserAuthenticationDataHandle userAuthenticationDataHandle;

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
}
