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
import java.net.ConnectException;
import java.net.URL;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import com.netflix.msl.MslConstants.ResponseCode;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;
import com.netflix.msl.msg.MslControl;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationData;

import mslcli.common.Pair;
import mslcli.client.msg.MessageConfig;
import mslcli.client.util.UserAuthenticationDataHandle;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.MslProperties;
import mslcli.common.util.MslStoreWrapper;
import mslcli.common.util.SharedUtil;

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

    private static final String CMD_HELP = "-help";
    private static final String CMD_LIST = "-list";
    private static final String CMD_QUIT = "-quit";

    public enum Status {
        OK(0, "Success"),
        ARG_ERROR    (1, "Invalid Arguments"),
        CFG_ERROR    (2, "Configuration File Error"),
        MSL_EXC_ERROR(3, "MSL Exception"),
        MSL_ERROR    (4, "Server App Error Reply"),
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

    public static void main(String[] args) {
        try {
            if (Arrays.asList(args).contains(CMD_HELP)) {
                help();
                exit(Status.OK);
            }
            if (args.length == 0) {
                System.err.println("Use " + CMD_HELP + " for help");
                exit(Status.ARG_ERROR);
            }

            final CmdArguments cmdParam = new CmdArguments(args);
        
            final ClientApp clientApp = new ClientApp(cmdParam);

            if (cmdParam.isInteractive()) {
                clientApp.sendMultipleRequests();
                exit(Status.OK);
            } else {
                Status status = clientApp.sendSingleRequest();
                exit(status);
            }
        } catch (ConfigurationException e) {
            System.err.println(e.getMessage());
            exit(Status.ARG_ERROR);
        } catch (IllegalCmdArgumentException e) {
            System.err.println(e.getMessage());
            exit(Status.ARG_ERROR);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            exit(Status.EXE_ERROR);
        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
            exit(Status.EXE_ERROR);
        }
    }

    private static String getMslExceptionInfo(final MslException e) {
        final MslError mslError = e.getError();
        final ResponseCode respCode = mslError.getResponseCode();
        return String.format("MslException: responseCode %d, Message %s", respCode, e.getMessage());
    }

    private static void exit(final Status status) {
        System.out.println("Exit Status " + status);
        System.exit(status.code);
    }

    private ClientApp(final CmdArguments cmdParam) throws ConfigurationException, IllegalCmdArgumentException, IOException {

        // save command-line arguments
        this.cmdParam = cmdParam;

        // load configuration from the configuration file
        this.mslProp = MslProperties.getInstance(SharedUtil.loadPropertiesFromFile(cmdParam.getConfigFilePath()));

        // initialize application context
        this.appCtx = AppContext.getInstance(mslProp, APP_ID);

        // initialize MSL Store - use wrapper to intercept selected MSL Store calls
        this.appCtx.setMslStoreWrapper(new AppMslStoreWrapper(appCtx));
    }

    /*
     * In a loop as a user to modify command-line arguments and then send a single request,
     * until a user enters "-quit" command.
     *
     * @return true if configuration was succesfully modified or left unchanged; false if QUIT option was entered
     * @throws IOException in case of user input reading error
     */

    private void sendMultipleRequests() throws IllegalCmdArgumentException, IOException {
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
    private Status sendSingleRequest() {
        Status status = Status.OK;

        try {
            // set verbose mode
            if (cmdParam.isVerbose()) {
                appCtx.getMslControl().setFilterFactory(new ConsoleFilterStreamFactory());
            }
            System.out.println("Options: " + cmdParam.getParameters());

            // initialize Client for the first time or whenever its identity changes
            if (!cmdParam.getEntityId().equals(clientId) || (client == null)) {
                clientId = cmdParam.getEntityId();
                client = null; // required for keeping the state, in case the next line throws exception
                client = new Client(appCtx, clientId);
            }

            client.setUserAuthenticationDataHandle(new AppUserAuthenticationDataHandle(cmdParam.getUserId(), mslProp));

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
                client.setKeyRequestData(kx, kxm);
            }

            // set request payload
            byte[] requestPayload = null;
            final String inputFile = cmdParam.getPayloadInputFile();
            requestPayload = cmdParam.getPayloadMessage();
            if (inputFile != null && requestPayload != null) {
                appCtx.error("Input File and Input Message cannot be both specified");
                return Status.ARG_ERROR;
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
                    System.out.println("Response: " + new String(response.getPayload()));
                }
            } else if (response.getErrorHeader() != null) {
                if (response.getErrorHeader().getErrorMessage() != null) {
                    System.err.println(String.format("ERROR: error_code %d, error_msg \"%s\"",
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
            System.err.println(getMslExceptionInfo(e));
            return Status.MSL_EXC_ERROR;
        } catch (ConfigurationException e) {
            System.err.println("Error: " + e.getMessage());
            return Status.CFG_ERROR;
        } catch (IllegalCmdArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            return Status.ARG_ERROR;
        } catch (ConnectException e) {
            System.err.println("Error: " + e.getMessage());
            return Status.COMM_ERROR;
        } catch (ExecutionException e) {
            System.err.println("Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            return Status.EXE_ERROR;
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            return Status.EXE_ERROR;
        } catch (InterruptedException e) {
            System.err.println("Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            return Status.EXE_ERROR;
        } catch (RuntimeException e) {
            System.err.println("Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            return Status.EXE_ERROR;
        }

        return status;
    }

    /*
     * helper
     */
    private static void help() {
        try {
            System.out.println(new String(SharedUtil.readFromFile(HELP_FILE)));
        } catch (IOException e) {
            System.err.println(String.format("Cannot read help file %s: %s", HELP_FILE, e.getMessage()));
        }
    }

    /*
     * This class facilitates on-demand fetching of user authentication data.
     * Other implementations may prompt users to enter their credentials from the console.
     */
    private static final class AppUserAuthenticationDataHandle implements UserAuthenticationDataHandle {
        AppUserAuthenticationDataHandle(final String userId, final MslProperties mslProp) {
            this.userId = userId;
            this.mslProp = mslProp;
        }

        @Override
        public UserAuthenticationData getUserAuthenticationData() {
            System.out.println("UserAuthentication Data requested");
            if (userId != null) {
                try {
                    final Pair<String,String> ep = mslProp.getEmailPassword(userId);
                    return new EmailPasswordAuthenticationData(ep.x, ep.y);
                } catch (ConfigurationException e) {
                    throw new IllegalArgumentException("Invalid Email-Password Configuration for User " + userId);
                }
            } else {
                return null;
            }
        }

        private final String userId;
        private final MslProperties mslProp;
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
                appCtx.info(String.format("MslStore: %s %s\n",
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

        private final AppContext appCtx;
    }
}
