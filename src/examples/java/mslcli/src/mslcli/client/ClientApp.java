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
import java.net.URL;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import com.netflix.msl.MslException;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.MslControl;

import mslcli.common.msg.MessageConfig;
import mslcli.common.util.SharedUtil;

import static mslcli.common.Constants.*;

/**
 * MSL client launcher program. Allows to configure message security policies and key exchange mechanism.
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class ClientApp {
    // Add BouncyCastle provider.
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // commands
    private static final String CMD_MSG  = "msg"; // send message
    private static final String CMD_CFG  = "cfg" ; // configure message properties
    private static final String CMD_KX   = "kx"  ; // select key exchange
    private static final String CMD_HELP = "help"; // help

    private static final List<String> supportedCommands =
        Collections.unmodifiableList(new ArrayList<String>(Arrays.asList(CMD_MSG, CMD_CFG, CMD_KX, CMD_HELP)));

    // Key Exchange strings are defined in Constants.java
    private static final Set<String> supportedKxTypes = Collections.unmodifiableSet(
        new HashSet<String>(Arrays.asList(KX_DH, KX_SWE, KX_AWE, KX_JWEL, KX_JWKL)));

    // Asymmetric Wrapped Key Exchange Mechanisms
    private static final Set<String> supportedAsymmetricWrappedExchangeMechanisms = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
                                                                            AsymmetricWrappedExchange.RequestData.Mechanism.JWE_RSA.toString(),
                                                                            AsymmetricWrappedExchange.RequestData.Mechanism.JWEJS_RSA.toString(),
                                                                            AsymmetricWrappedExchange.RequestData.Mechanism.JWK_RSA.toString(),
                                                                            AsymmetricWrappedExchange.RequestData.Mechanism.JWK_RSAES.toString())));
    private static final String MSG_ENCRYPTION = "Encrypted";
    private static final String MSG_INTEGRITY  = "Integrity Protected";
    private static final String MSG_NONREPLAY  = "Non-Replayable";

    private static final String YES   = "y";
    private static final String NO    = "n";
    private static final String QUIT  = "q";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Specify remote URL");
            System.exit(1);
        }

        /* An application should only use one instance of MslControl for all MSL communication.
         * This class is thread-safe.
         * Passing 0 parameter leads to MslControl executing on the caller's thread.
         */
        final MslControl mslCtrl = new MslControl(0);
        if (args.length > 1) {
            mslCtrl.setFilterFactory(new ConsoleFilterStreamFactory());
        }

        final URL remoteUrl = new URL(args[0]);
        final Client client = new Client(CLIENT_ID, mslCtrl);
        final MessageConfig cfg = new MessageConfig();
        cfg.isEncrypted = true;
        cfg.isIntegrityProtected = true;
        cfg.isNonReplayable = false;

        String cmd;
        while (!QUIT.equalsIgnoreCase(cmd = SharedUtil.readInput(String.format("Command(\"%s\" to exit) %s", QUIT, supportedCommands.toString())))) {
            if (CMD_KX.equalsIgnoreCase(cmd)) {
                setKeyExchange(client);
            } else if (CMD_CFG.equalsIgnoreCase(cmd)) {
                setConfig(cfg);
            } else if (CMD_MSG.equalsIgnoreCase(cmd)) {
                sendMessages(client, cfg, remoteUrl);
            } else if (CMD_HELP.equalsIgnoreCase(cmd)) {
                System.out.println(help());
            }
        }
    }

    private static String help() {
        final String pad = "    ";
        final StringBuilder sb = new StringBuilder(); 
            sb.append("commands:\n")
              .append(CMD_KX).append(" - select Key Exchange Type\n")
              .append(pad).append(KX_DH).append(" - Diffie-Hellman Key Exchange\n")
              .append(pad).append(KX_SWE).append(" - Symmetric Wrapped Key Exchange\n")
              .append(pad).append(KX_AWE).append(" - Awymmetric Wrapped Key Exchange\n")
              .append(pad).append(pad).append("Mechanisms:\n")
              .append(pad).append(pad).append(AsymmetricWrappedExchange.RequestData.Mechanism.JWE_RSA).append(" - RSA-OAEP JSON Web Encryption JSON Serialization\n")
              .append(pad).append(pad).append(AsymmetricWrappedExchange.RequestData.Mechanism.JWEJS_RSA).append(" - RSA-OAEP JSON Web Encryption Compact Serialization\n")
              .append(pad).append(pad).append(AsymmetricWrappedExchange.RequestData.Mechanism.JWK_RSA).append(" - RSA-OAEP JSON Web Key\n")
              .append(pad).append(pad).append(AsymmetricWrappedExchange.RequestData.Mechanism.JWK_RSAES).append("- RSA PKCS#1 JSON Web Key\n")
              .append(pad).append(KX_JWEL).append(" - JSON Web Encryption Ladder Key Exchange\n")
              .append(pad).append(KX_JWKL).append(" - JSON Web Key Ladder Key Exchange\n")
              .append(CMD_CFG).append(" - set message security properties:\n")
              .append(pad).append(MSG_ENCRYPTION).append(" - Encryption ON/OFF\n")
              .append(pad).append(MSG_INTEGRITY).append(" - Integrity Protection ON/OFF\n")
              .append(pad).append(MSG_NONREPLAY).append(" - Non-Replay ON/OFF\n")
              .append(CMD_MSG).append(" - send multiple text messages using the selected key exchange mechanism and message security properties\n")
              .append(pad).append("enter \"q\" to go back to the command menu\n");
        return sb.toString();
    }

    /*
     * Set client's key exchange data. Some key exchange types require setting specific mechanism.
     * Real-life clients may support just one key exchange type.
     *
     * This method may need to be called repetitively for key exchanges requiring ephemeral keys.
     */
    private static void setKeyExchange(final Client client) throws IOException, MslException {
        String kxType;
        while (!QUIT.equalsIgnoreCase(kxType = SharedUtil.readInput(String.format("KeyExchange(\"%s\" to skip) %s", QUIT, supportedKxTypes.toString())))) {
            if (supportedKxTypes.contains(kxType)) {
                String mechanism = null;
                if (KX_AWE.equals(kxType)) {
                    do {
                        mechanism = SharedUtil.readInput(String.format("Mechanism%s", supportedAsymmetricWrappedExchangeMechanisms.toString()));
                    } while (!supportedAsymmetricWrappedExchangeMechanisms.contains(mechanism));
                }
                client.setKeyRequestData(kxType, mechanism);
                break;
            }
        }
    }

    /*
     * Set message security basic properties, such as encryption, integrity protection, and non-renewability.
     * Real-life apps may set different parameters for each message, depending on security requirements.
     * This is why MessageConfig instance is passed in every Client.sendrequest() call.
     */
    private static void setConfig(final MessageConfig cfg) throws IOException {
        cfg.isEncrypted          = SharedUtil.readBoolean(MSG_ENCRYPTION, cfg.isEncrypted         , YES, NO);
        cfg.isIntegrityProtected = SharedUtil.readBoolean(MSG_INTEGRITY , cfg.isIntegrityProtected, YES, NO);
        cfg.isNonReplayable      = SharedUtil.readBoolean(MSG_NONREPLAY , cfg.isNonReplayable     , YES, NO);
        System.out.println(cfg.toString());
    }

    /*
     * Send multiple text messages, using selected target URL, message configuration, and key exchange mechanism.
     */
    private static void sendMessages(final Client client, final MessageConfig cfg, final URL remoteUrl)
        throws ExecutionException, InterruptedException, IOException, MslException
    {
        System.out.println(cfg.toString());
        String msg;
        while (!QUIT.equalsIgnoreCase(msg = SharedUtil.readInput(String.format("Message(\"%s\" to finish)", QUIT)))) {
            final byte[] response = client.sendRequest(msg.getBytes(), cfg, remoteUrl);
            if (response != null) {
                System.out.println("\nResponse: " + new String(response));
            }
        }
    }
}
