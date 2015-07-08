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

import java.io.Console;
import java.io.InputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URL;
import java.security.KeyPair;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.JsonWebEncryptionLadderExchange;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationData;

import mslcli.common.Pair;
import mslcli.client.msg.MessageConfig;
import mslcli.client.util.KeyRequestDataHandle;
import mslcli.client.util.UserAuthenticationDataHandle;
import mslcli.common.Triplet;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.ConfigurationRuntimeException;
import mslcli.common.util.MslProperties;
import mslcli.common.util.MslStoreWrapper;
import mslcli.common.util.SharedUtil;
import mslcli.common.util.WrapCryptoContextRepositoryWrapper;

import static mslcli.client.CmdArguments.*;

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

    private static final String CMD_PROMPT = "args"; // command prompt
    private static final String APP_ID = "client_app"; // client app id

    private static final String HELP_FILE = "mslclient_manual.txt";

    private static final String CMD_HELP = "help";
    private static final String CMD_LIST = "list";
    private static final String CMD_QUIT = "quit";
    private static final String CMD_HINT = "?";

    public enum Status {
        OK(0, "Success"),
        ARG_ERROR    (1, "Invalid Arguments"),
        CFG_ERROR    (2, "Configuration File Error"),
        MSL_EXC_ERROR(3, "MSL Exception"),
        MSL_ERROR    (4, "Server MSL Error Reply"),
        COMM_ERROR   (5, "Server Communication Error"),
        EXE_ERROR    (6, "Internal Execution Error");

        private final int code;
        private final String info;

        Status(final int code, final String info) {
            this.code = code;
            this.info = info;
        }

        @Override
        public String toString() {
            return String.format("%d: %s", code, info);
        }
    }

    private final CmdArguments cmdParam;
    private final MslProperties mslProp;
    private final AppContext appCtx;
    private Client client;
    private String clientId = null;
    private AppKeyRequestDataHandle keyRequestDataHandle = null;

    /*
     * Launcher of MSL CLI client. See user manual in HELP_FILE.
     */
    public static void main(String[] args) {
        Status status = Status.OK;
        try {
            if (args.length == 0) {
                System.err.println("Use " + CMD_HELP + " for help");
                status = Status.ARG_ERROR;
            } else if (CMD_HELP.equalsIgnoreCase(args[0])) {
                help();
                status = Status.OK;
            } else {
                final CmdArguments cmdParam = new CmdArguments(args);
                final ClientApp clientApp = new ClientApp(cmdParam);
                if (cmdParam.isInteractive()) {
                    clientApp.sendMultipleRequests();
                    status = Status.OK;
                } else {
                    status = clientApp.sendSingleRequest();
                }
            }
        } catch (ConfigurationException e) {
            System.err.println(e.getMessage());
            status = Status.CFG_ERROR;
        } catch (IllegalCmdArgumentException e) {
            System.err.println(e.getMessage());
            status = Status.ARG_ERROR;
        } catch (IOException e) {
            System.err.println(e.getMessage());
            status = Status.EXE_ERROR;
            SharedUtil.getRootCause(e).printStackTrace(System.err);
        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
            status = Status.EXE_ERROR;
            SharedUtil.getRootCause(e).printStackTrace(System.err);
        }
        System.out.println("Exit Status " + status);
        System.exit(status.code);
    }

    /*
     * ClientApp holds the instance of one Client and some other objects which are global for the application.
     * Instance of Client is supposed to be re-instantiated only when its entity identity changes,
     * which is only applicable in the interactive mode. Changing entity identity within a given Client
     * instance would be too convoluted; it makes sense to permanently bind Client with its entity ID.
     *
     * @param encapsulation of command-line arguments
     */
    public ClientApp(final CmdArguments cmdParam) throws ConfigurationException, IllegalCmdArgumentException, IOException {
        if (cmdParam == null) {
            throw new IllegalArgumentException("NULL Arguments");
        }

        // save command-line arguments
        this.cmdParam = cmdParam;

        // load configuration from the configuration file
        this.mslProp = MslProperties.getInstance(SharedUtil.loadPropertiesFromFile(cmdParam.getConfigFilePath()));

        final String pskFile = cmdParam.getPskFile();
        if (pskFile != null) {
            final Triplet<String,String,String> pskEntry;
            try {
                pskEntry = SharedUtil.readPskFile(pskFile);
            } catch (IOException e) {
                throw new ConfigurationException(e.getMessage());
            }
            cmdParam.merge(new CmdArguments(new String[] { CmdArguments.P_EID, pskEntry.x }));
            mslProp.addPresharedKeys(pskEntry);
        }

        // initialize application context
        this.appCtx = AppContext.getInstance(mslProp, APP_ID);

        // initialize MSL Store - use wrapper to intercept selected MSL Store calls
        this.appCtx.setMslStoreWrapper(new AppMslStoreWrapper(appCtx));

        // initialize WrapCryptoContextRepositoryWrapper to intercept WrapCryptoContextRepository calls
        this.appCtx.setWrapCryptoContextRepositoryWrapper(new AppWrapCryptoContextRepositoryWrapper(appCtx));
    }

    /*
     * In a loop as a user to modify command-line arguments and then send a single request,
     * until a user enters "-quit" command.
     *
     * @return true if configuration was succesfully modified or left unchanged; false if QUIT option was entered
     * @throws IOException in case of user input reading error
     */

    public void sendMultipleRequests() throws IllegalCmdArgumentException, IOException {
        while (true) {
            final String options = SharedUtil.readInput(CMD_PROMPT);
            if (CMD_QUIT.equalsIgnoreCase(options)) {
                return;
            }
            if (CMD_HELP.equalsIgnoreCase(options)) {
                help();
                continue;
            }
            if (CMD_LIST.equalsIgnoreCase(options)) {
                System.out.println(cmdParam.getParameters());
                continue;
            }
            if (CMD_HINT.equalsIgnoreCase(options)) {
                hint();
                continue;
            }
            try {
                // parse entered parameters just  like command-line arguments
                if (options != null && !options.trim().isEmpty()) {
                    final CmdArguments p = new CmdArguments(SharedUtil.split(options));
                    cmdParam.merge(p);
                }
                final Status status = sendSingleRequest();
                if (status != Status.OK) {
                    System.out.println("Status: " + status.toString());
                }
            } catch (IllegalCmdArgumentException e) {
                System.err.println(e.getMessage());
            } catch (RuntimeException e) {
                System.err.println(e.getMessage());
            }
        }
    }

    /*
     * send single request
     */
    public Status sendSingleRequest() {
        Status status = Status.OK;

        try_label: try {
            // set verbose mode
            if (cmdParam.isVerbose()) {
                appCtx.getMslControl().setFilterFactory(new ConsoleFilterStreamFactory());
            } else {
                appCtx.getMslControl().setFilterFactory(null);
            }
            System.out.println("Options: " + cmdParam.getParameters());

            // initialize Client for the first time or whenever its identity changes
            if (!cmdParam.getEntityId().equals(clientId) || (client == null)) {
                clientId = cmdParam.getEntityId();
                client = null; // required for keeping the state, in case the next line throws exception
                keyRequestDataHandle = new AppKeyRequestDataHandle(appCtx, clientId);
                client = new Client(appCtx, clientId, new AppUserAuthenticationDataHandle(cmdParam.getUserId(), mslProp, cmdParam.isInteractive()),
                                                      keyRequestDataHandle);
            }

            // set message mslProperties
            final MessageConfig mcfg = new MessageConfig();
            mcfg.userId = cmdParam.getUserId();
            mcfg.isEncrypted = cmdParam.isEncrypted();
            mcfg.isIntegrityProtected = cmdParam.isIntegrityProtected();
            mcfg.isNonReplayable = cmdParam.isNonReplayable();

            // set key exchange scheme / mechanism
            final String kx = cmdParam.getKeyExchangeScheme();
            if (kx != null) {
                final String kxm = cmdParam.getKeyExchangeMechanism();
                keyRequestDataHandle.setKeyExchange(kx, kxm);
            }

            // set request payload
            byte[] requestPayload = null;
            final String inputFile = cmdParam.getPayloadInputFile();
            requestPayload = cmdParam.getPayloadMessage();
            if (inputFile != null && requestPayload != null) {
                appCtx.error("Input File and Input Message cannot be both specified");
                status = Status.ARG_ERROR;
                break try_label;
            }
            if (inputFile != null) {
                requestPayload = SharedUtil.readFromFile(inputFile);
            } else {
                if (requestPayload == null) {
                    requestPayload = new byte[0];
                }
            }

            // send request and process response
            final String outputFile = cmdParam.getPayloadOutputFile();
            final URL url = cmdParam.getUrl();
            final Client.Response response = client.sendRequest(requestPayload, mcfg, url);
            // Non-NULL response payload - good
            if (response.getPayload() != null) {
                if (outputFile != null) {
                    SharedUtil.saveToFile(outputFile, response.getPayload());
                } else {
                    System.out.println("Response: " + new String(response.getPayload(), MslConstants.DEFAULT_CHARSET));
                }
                status = Status.OK;
            } else if (response.getErrorHeader() != null) {
                if (response.getErrorHeader().getErrorMessage() != null) {
                    System.err.println(String.format("MSL RESPONSE ERROR: error_code %d, error_msg \"%s\"",
                        response.getErrorHeader().getErrorCode().intValue(),
                        response.getErrorHeader().getErrorMessage()));
                } else {
                    System.err.println(String.format("ERROR: %s" + response.getErrorHeader().toJSONString()));
                }
                status = Status.MSL_ERROR;
            } else {
                System.out.println("Response with no payload or error header ???");
                status = Status.MSL_ERROR;
            }
        } catch (MslException e) {
            System.err.println(SharedUtil.getMslExceptionInfo(e));
            status = Status.MSL_EXC_ERROR;
            SharedUtil.getRootCause(e).printStackTrace(System.err);
        } catch (ConfigurationException e) {
            System.err.println("Error: " + e.getMessage());
            status = Status.CFG_ERROR;
        } catch (ConfigurationRuntimeException e) {
            System.err.println("Error: " + e.getCause().getMessage());
            status = Status.CFG_ERROR;
        } catch (IllegalCmdArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            status = Status.ARG_ERROR;
        } catch (ConnectException e) {
            System.err.println("Error: " + e.getMessage());
            status = Status.COMM_ERROR;
        } catch (ExecutionException e) {
            final Throwable thr = SharedUtil.getRootCause(e);
            if (thr instanceof ConfigurationException) {
                System.err.println("Error: " + thr.getMessage());
                status = Status.CFG_ERROR;
            } else if (thr instanceof MslException) {
                System.err.println(SharedUtil.getMslExceptionInfo((MslException)thr));
                status = Status.MSL_EXC_ERROR;
                SharedUtil.getRootCause(e).printStackTrace(System.err);
            } else if (thr instanceof ConnectException) {
                System.err.println("Error: " + thr.getMessage());
                status = Status.COMM_ERROR;
            } else {
                System.err.println("Error: " + thr.getMessage());
                thr.printStackTrace(System.err);
                status = Status.EXE_ERROR;
            }
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            status = Status.EXE_ERROR;
        } catch (InterruptedException e) {
            System.err.println("Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            status = Status.EXE_ERROR;
        } catch (RuntimeException e) {
            System.err.println("Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            status = Status.EXE_ERROR;
        }

        return status;
    }

    /*
     * This class facilitates on-demand fetching of user authentication data.
     * Other implementations may prompt users to enter their credentials from the console.
     */
    private static final class AppUserAuthenticationDataHandle implements UserAuthenticationDataHandle {
        AppUserAuthenticationDataHandle(final String userId, final MslProperties mslProp, final boolean interactive) {
            this.userId = userId;
            this.mslProp = mslProp;
            this.interactive = interactive;
        }

        @Override
        public UserAuthenticationData getUserAuthenticationData() {
            System.out.println("UserAuthentication Data requested");
            if (userId != null) {
                try {
                    final Pair<String,String> ep = mslProp.getEmailPassword(userId);
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

        private final String userId;
        private final MslProperties mslProp;
        private final boolean interactive;
    }

    /*
     * This class facilitates on-demand fetching of key request data and configuring this data on the fly.
     */
    private static final class AppKeyRequestDataHandle implements KeyRequestDataHandle {
        AppKeyRequestDataHandle(final AppContext appCtx, final String clientId) {
            this.appCtx = appCtx;
            this.clientId = clientId;
            this.keyRequestDataSet = new HashSet<KeyRequestData>();
        }

        @Override
        public synchronized Set<KeyRequestData> getKeyRequestData() {
            appCtx.info("Requesting Key Request Data");
            return Collections.<KeyRequestData>unmodifiableSet(keyRequestDataSet);
        }

        /*
         * Set key request data for specific key request scheme and (if applicable) mechanism.
         * @param kxsName key exchange scheme name
         * @param kxmName key exchange mechanism name
         */
        private synchronized void setKeyExchange(final String kxsName, final String kxmName)
            throws ConfigurationException, IllegalCmdArgumentException, ConfigurationException, MslKeyExchangeException {
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
                final byte[] wrapdata;
                if (m == JsonWebEncryptionLadderExchange.Mechanism.WRAP) {
                    wrapdata = appCtx.getWrapCryptoContextRepository().getLastWrapdata();
                    if (wrapdata == null) {
                        throw new IllegalCmdArgumentException(String.format("No Key Wrapping Data Found for {%s %s}", kxScheme.name(), m));
                    }
                } else {
                    wrapdata = null;
                }
                keyRequestDataSet.add(new JsonWebEncryptionLadderExchange.RequestData(m, wrapdata));
            } else if (kxScheme == KeyExchangeScheme.JWK_LADDER) {
                final JsonWebKeyLadderExchange.Mechanism m = getKeyExchangeMechanism(
                    JsonWebKeyLadderExchange.Mechanism.class, kxScheme, kxmName);
                final byte[] wrapdata;
                if (m == JsonWebKeyLadderExchange.Mechanism.WRAP) {
                    wrapdata = appCtx.getWrapCryptoContextRepository().getLastWrapdata();
                    if (wrapdata == null) {
                        throw new IllegalCmdArgumentException(String.format("No Key Wrapping Data Found for {%s %s}", kxScheme.name(), m));
                    }
                } else {
                    wrapdata = null;
                }
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

        private final AppContext appCtx;
        private final String clientId;
        private final Set<KeyRequestData> keyRequestDataSet; 
        /* Cached RSA Key Pair for asymmetric key wrap key exchange to avoid expensive key pair generation.
         * This is an optimization specific to this application, to avoid annoying delays in generating
         * 4096-bit RSA key pairs. Real-life implementations should not re-use key wrapping keys
         * too many times.
         */
        private KeyPair aweKeyPair = null;
        /* default asymmetrik key wrap exchange key pair id - the value should not matter */
        private static final String DEFAULT_AWE_KEY_PAIR_ID = "default_awe_key_id";
    }

    /*
     * This is a class to serve as an interceptor to all MslStore calls.
     * It can override only the methods in MslStore the app cares about.
     * This sample implementation just prints out the information about
     * calling some selected MslStore methods.
     */
    private static final class AppMslStoreWrapper extends MslStoreWrapper {
        private AppMslStoreWrapper(final AppContext appCtx) {
            if (appCtx == null) {
                throw new IllegalArgumentException("NULL app context");
            }
            this.appCtx = appCtx;
        }

        @Override
        public void setCryptoContext(final MasterToken masterToken, final ICryptoContext cryptoContext) {
            if (masterToken == null) {
                appCtx.info("MslStore: setting crypto context with NULL MasterToken???");
            } else {
                appCtx.info(String.format("MslStore: %s %s",
                    (cryptoContext != null)? "Adding" : "Removing", SharedUtil.getMasterTokenInfo(masterToken)));
            }
            super.setCryptoContext(masterToken, cryptoContext);
        }

        @Override
        public void removeCryptoContext(final MasterToken masterToken) {
            appCtx.info("MslStore: Removing Crypto Context for " + SharedUtil.getMasterTokenInfo(masterToken));
            super.removeCryptoContext(masterToken);
        }

        @Override
        public void clearCryptoContexts() {
            appCtx.info("MslStore: Clear Crypto Contexts");
            super.clearCryptoContexts();
        }

        @Override
        public void addUserIdToken(final String userId, final UserIdToken userIdToken) throws MslException {
            appCtx.info(String.format("MslStore: Adding %s for userId %s", SharedUtil.getUserIdTokenInfo(userIdToken), userId));
            super.addUserIdToken(userId, userIdToken);
        }

        @Override
        public void removeUserIdToken(final UserIdToken userIdToken) {
            appCtx.info("MslStore: Removing " + SharedUtil.getUserIdTokenInfo(userIdToken));
            super.removeUserIdToken(userIdToken);
        }

        @Override
        public UserIdToken getUserIdToken(final String userId) {
            appCtx.info("MslStore: Getting UserIdToken for user ID " + userId);
            return super.getUserIdToken(userId);
        }

        @Override
        public void addServiceTokens(final Set<ServiceToken> tokens) throws MslException {
            if (tokens != null && !tokens.isEmpty()) {
                final StringBuilder sb = new StringBuilder();
                for (ServiceToken st : tokens) {
                    sb.append(SharedUtil.getServiceTokenInfo(st)).append("\n");
                }
                appCtx.info("MslStore: Adding Service Tokens\n" + sb.toString());
            }
            super.addServiceTokens(tokens);
        }

        @Override
        public void removeServiceTokens(final String name, final MasterToken masterToken, final UserIdToken userIdToken) throws MslException {
            appCtx.info(String.format("MslStore: Removing Service Tokens %s for %s %s", name,
                SharedUtil.getMasterTokenInfo(masterToken), SharedUtil.getUserIdTokenInfo(userIdToken)));
            super.removeServiceTokens(name, masterToken, userIdToken);
        }

        private final AppContext appCtx;
    }

    /*
     * convenience WrapCryptoContextRepository wrapper class to trace all calls
     */
    private static final class AppWrapCryptoContextRepositoryWrapper extends WrapCryptoContextRepositoryWrapper {
        private AppWrapCryptoContextRepositoryWrapper(final AppContext appCtx) {
            if (appCtx == null) {
                throw new IllegalArgumentException("NULL app context");
            }
            this.appCtx = appCtx;
        }

        @Override
        public void addCryptoContext(final byte[] wrapdata, final ICryptoContext cryptoContext) {
            appCtx.info("WrapCryptoContextRepositoryWrapper: addCryptoContext " + ((cryptoContext != null) ? cryptoContext.getClass().getName() : "null"));
            super.addCryptoContext(wrapdata, cryptoContext);
        }

        @Override
        public ICryptoContext getCryptoContext(final byte[] wrapdata) {
            appCtx.info("WrapCryptoContextRepositoryWrapper: getCryptoContext");
            return super.getCryptoContext(wrapdata);
        }

        @Override
        public void removeCryptoContext(final byte[] wrapdata) {
            appCtx.info("WrapCryptoContextRepositoryWrapper: removeCryptoContext");
            super.removeCryptoContext(wrapdata);
        }
        private final AppContext appCtx;
    }

    /*
     * helper - print help file
     */
    private static void help() {
        InputStream input = null;
        try {
            input = ClientApp.class.getResourceAsStream(HELP_FILE);
            final String helpInfo = new String(SharedUtil.readIntoArray(input), MslConstants.DEFAULT_CHARSET);
            System.out.println(helpInfo);
        } catch (Exception e) {
            System.err.println(String.format("Cannot read help file %s: %s", HELP_FILE, e.getMessage()));
        } finally {
            if (input != null) try { input.close(); } catch (Exception ignore) {}
        }
    }

    /*
     * helper - interactive mode hint
     */
    private static void hint() {
        System.out.println("Choices:");
        System.out.println("a) Modify Command-line arguments, if any need to be modified, and press Enter to send a message.");
        System.out.println("   Use exactly the same syntax as from the command line.");
        System.out.println("b) Type \"list\" for listing currently selected command-line arguments.");
        System.out.println("c) Type \"help\" for the detailed instructions on using this tool.");
        System.out.println("d) Type \"quit\" to quit this tool.");
    }
}
