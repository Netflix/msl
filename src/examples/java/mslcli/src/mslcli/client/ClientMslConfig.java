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

import java.io.Console;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.JsonWebEncryptionLadderExchange;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationData;

import mslcli.client.util.ClientAuthenticationUtils;
import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.MslConfig;
import mslcli.common.Pair;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;

/**
 * <p>The configuration class for specific MSl client entity ID.
 *    Each time the app changes client entity ID, new instance
 *    needs to be created.</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class ClientMslConfig extends MslConfig {
    public ClientMslConfig(final AppContext appCtx, final String clientId, final CmdArguments args)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        super(appCtx,
              args,
              clientId,
              new PresharedAuthenticationData(clientId),
              new ClientAuthenticationUtils(clientId, appCtx)
             );
    }

    /* Cached RSA Key Pair for asymmetric key wrap key exchange to avoid expensive key pair generation.
     * This is an optimization specific to this application, to avoid annoying delays in generating
     * 4096-bit RSA key pairs. Real-life implementations should not re-use key wrapping keys
     * too many times.
     */
    private KeyPair aweKeyPair = null;
    /* default asymmetric key wrap exchange key pair id - the value should not matter */
    private static final String DEFAULT_AWE_KEY_PAIR_ID = "default_awe_key_id";

    public KeyRequestData getKeyRequestData(final String kxsName, final String kxmName)
        throws ConfigurationException, IllegalCmdArgumentException, MslKeyExchangeException
    {
        if (kxsName == null || kxsName.trim().isEmpty()) {
            throw new IllegalArgumentException("NULL Key Exchange Type");
        }
        final KeyExchangeScheme kxScheme = KeyExchangeScheme.getScheme(kxsName.trim());
        if (kxScheme == null) {
            throw new IllegalCmdArgumentException(String.format("Invalid Key Exchange Type %s: valid %s", kxsName.trim(), KeyExchangeScheme.values()));
        }
        final KeyRequestData keyRequestData;

        if (kxScheme == KeyExchangeScheme.DIFFIE_HELLMAN) {
            if (kxmName != null) {
                throw new IllegalCmdArgumentException("No Key Wrapping Mechanism Needed for Key Exchange " + kxScheme.name());
            }
            final String diffieHellmanParametersId = appCtx.getDiffieHellmanParametersId(entityId);
            final KeyPair dhKeyPair = appCtx.generateDiffieHellmanKeys(diffieHellmanParametersId);
            keyRequestData = new DiffieHellmanExchange.RequestData(diffieHellmanParametersId,
                ((DHPublicKey)dhKeyPair.getPublic()).getY(), (DHPrivateKey)dhKeyPair.getPrivate());
        } else if (kxScheme == KeyExchangeScheme.SYMMETRIC_WRAPPED) {
            final SymmetricWrappedExchange.KeyId keyId = getKeyExchangeMechanism(
                SymmetricWrappedExchange.KeyId.class, kxScheme, kxmName);
            keyRequestData = new SymmetricWrappedExchange.RequestData(keyId);
        } else if (kxScheme == KeyExchangeScheme.ASYMMETRIC_WRAPPED) {
            final AsymmetricWrappedExchange.RequestData.Mechanism m = getKeyExchangeMechanism(
                AsymmetricWrappedExchange.RequestData.Mechanism.class, kxScheme, kxmName);
            if (aweKeyPair == null) {
                aweKeyPair = appCtx.generateAsymmetricWrappedExchangeKeyPair();
            }
            keyRequestData = new AsymmetricWrappedExchange.RequestData(DEFAULT_AWE_KEY_PAIR_ID, m, aweKeyPair.getPublic(), aweKeyPair.getPrivate());
        } else if (kxScheme == KeyExchangeScheme.JWE_LADDER) {
            final JsonWebEncryptionLadderExchange.Mechanism m = getKeyExchangeMechanism(
                JsonWebEncryptionLadderExchange.Mechanism.class, kxScheme, kxmName);
            final byte[] wrapdata;
            if (m == JsonWebEncryptionLadderExchange.Mechanism.WRAP) {
                wrapdata = super.getWrapCryptoContextRepository(kxScheme).getLastWrapdata();
                if (wrapdata == null) {
                    throw new IllegalCmdArgumentException(String.format("No Key Wrapping Data Found for {%s %s}", kxScheme.name(), m));
                }
            } else {
                wrapdata = null;
            }
            keyRequestData = new JsonWebEncryptionLadderExchange.RequestData(m, wrapdata);

       } else if (kxScheme == KeyExchangeScheme.JWK_LADDER) {
            final JsonWebKeyLadderExchange.Mechanism m = getKeyExchangeMechanism(
                JsonWebKeyLadderExchange.Mechanism.class, kxScheme, kxmName);
            final byte[] wrapdata;
            if (m == JsonWebKeyLadderExchange.Mechanism.WRAP) {
                wrapdata = super.getWrapCryptoContextRepository(kxScheme).getLastWrapdata();
                if (wrapdata == null) {
                    throw new IllegalCmdArgumentException(String.format("No Key Wrapping Data Found for {%s %s}", kxScheme.name(), m));
                }
            } else {
                wrapdata = null;
            }
            keyRequestData = new JsonWebKeyLadderExchange.RequestData(m, wrapdata);
        } else {
            throw new IllegalCmdArgumentException("Unsupported Key Exchange Scheme " + kxScheme);
        }

        return keyRequestData;
    }

    public UserAuthenticationData getUserAuthenticationData(final String userId, boolean interactive) {
        if (userId != null) {
            try {
                final Pair<String,String> ep = appCtx.getProperties().getEmailPassword(userId);
                return new EmailPasswordAuthenticationData(ep.x, ep.y);
            } catch (ConfigurationException e) {
                if (interactive) {
                    final Console cons = System.console();
                    if (cons != null) {
                        final String email = cons.readLine("Email> ");
                        final char[] pwd = cons.readPassword("Password> ");
                        return new EmailPasswordAuthenticationData(email, new String(pwd));
                    } else {
                        throw new IllegalArgumentException("Invalid Email-Password Configuration for User " + userId);
                    }
                } else {
                    throw new IllegalArgumentException("Invalid Email-Password Configuration for User " + userId);
                }
            }
        } else {
            return null;
        }
    }

    /**
     * convenience method
     * @param clazz class defining Enum values for key exchange mechanisms for a given key exchange scheme
     * @param keyExchangeScheme key exchange scheme
     * @param kxmName key exchange mechanism name
     * @return key eachange mechanism Enum value
     */
    protected static <T extends Enum<T>> T getKeyExchangeMechanism(final Class<T> clazz, final KeyExchangeScheme keyExchangeScheme, final String kxmName)
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
}
