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

import java.io.InputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URL;
import java.security.Security;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.userauth.UserAuthenticationData;

import mslcli.common.MslConfig;
import mslcli.client.msg.MessageConfig;
import mslcli.client.util.KeyRequestDataHandle;
import mslcli.client.util.UserAuthenticationDataHandle;
import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.Triplet;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.ConfigurationRuntimeException;
import mslcli.common.util.MslProperties;
import mslcli.common.util.SharedUtil;
import mslcli.common.util.WrapCryptoContextRepositoryWrapper;

/**
 * <p>
 * MSL client launcher program. Allows sending a single or multiple MSL messages to one or more MLS
 * servers, using different message MSL security configuration options.
 * </p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class ClientApp {
    // Add BouncyCastle provider.
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String CMD_PROMPT = "args"; // command prompt

    private static final String HELP_FILE = "mslclient_manual.txt";

    private static final String CMD_HELP = "help";
    private static final String CMD_LIST = "list";
    private static final String CMD_SAVE = "save";
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
                clientApp.shutdown();
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
        this.appCtx = AppContext.getInstance(mslProp);
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
            if (CMD_SAVE.equalsIgnoreCase(options)) {
                if (client != null)
                    client.saveMslStore();
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
                if (client != null)
                    client.saveMslStore();
                client = null; // required for keeping the state, in case the next line throws exception
                final ClientMslConfig mslCfg = new ClientMslConfig(appCtx, cmdParam);
                keyRequestDataHandle = new AppKeyRequestDataHandle(appCtx, mslCfg);
                client = new Client(appCtx, new AppUserAuthenticationDataHandle(mslCfg, cmdParam.isInteractive()),
                                    keyRequestDataHandle, mslCfg);
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
                    SharedUtil.saveToFile(outputFile, response.getPayload(), false /*overwrite*/);
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

    /**
     * shutdown activities
     */
    public void shutdown() throws IOException {
        if (client != null)
            client.saveMslStore();
    }

    /*
     * This class facilitates on-demand fetching of user authentication data.
     * Other implementations may prompt users to enter their credentials from the console.
     */
    private static final class AppUserAuthenticationDataHandle implements UserAuthenticationDataHandle {
        AppUserAuthenticationDataHandle(final ClientMslConfig mslCfg, final boolean interactive) {
            this.mslCfg = mslCfg;
            this.interactive = interactive;
        }

        @Override
        public UserAuthenticationData getUserAuthenticationData(final String userId) {
            return mslCfg.getUserAuthenticationData(userId, interactive);
        }
        private final ClientMslConfig mslCfg;
        private final boolean interactive;
    }

    /*
     * This class facilitates on-demand fetching of key request data and configuring this data on the fly.
     */
    private static final class AppKeyRequestDataHandle implements KeyRequestDataHandle {
        AppKeyRequestDataHandle(final AppContext appCtx, final ClientMslConfig mslConfig) {
            this.appCtx = appCtx;
            this.mslConfig = mslConfig;
            this.keyRequestDataSet = new HashSet<KeyRequestData>();
            this.lastKxsName = null;
            this.lastKxmName = null;
            this.lastRequested = false;
        }

        @Override
        public synchronized Set<KeyRequestData> getKeyRequestData() {
            appCtx.info(String.format("%s: Requesting Key Request Data", this));
            lastRequested = true;
            return Collections.<KeyRequestData>unmodifiableSet(keyRequestDataSet);
        }

        /*
         * Set key request data for specific key request scheme and (if applicable) mechanism.
         * @param kxsName key exchange scheme name
         * @param kxmName key exchange mechanism name
         */
        private synchronized void setKeyExchange(final String kxsName, final String kxmName)
            throws ConfigurationException, IllegalCmdArgumentException, MslKeyExchangeException {
            if (SharedUtil.safeEqual(kxsName, lastKxsName) && SharedUtil.safeEqual(kxmName, lastKxmName) && !lastRequested)
                return;
            final KeyRequestData keyRequestData = mslConfig.getKeyRequestData(kxsName, kxmName);
            keyRequestDataSet.clear();
            keyRequestDataSet.add(keyRequestData);
            lastKxsName = kxsName;
            lastKxmName = kxmName;
            lastRequested = false;
        }

        @Override
        public String toString() {
            return String.format("KeyRequestDataHandle[%s]", mslConfig.getEntityId());
        }

        private final AppContext appCtx;
        private final ClientMslConfig mslConfig;
        private final Set<KeyRequestData> keyRequestDataSet;
        private String lastKxsName;
        private String lastKxmName;
        private boolean lastRequested;
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
        System.out.println(String.format("b) Type \"%s\" for listing currently selected command-line arguments.", CMD_LIST));
        System.out.println(String.format("c) Type \"%s\" for the detailed instructions on using this tool.", CMD_HELP));
        System.out.println(String.format("d) Type \"%s\" to save MSL store to the disk. MSL store is saved automatically on exit.", CMD_SAVE));
        System.out.println(String.format("e) Type \"%s\" to quit this tool.", CMD_QUIT));
    }
}
