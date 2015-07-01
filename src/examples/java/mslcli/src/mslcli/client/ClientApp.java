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

    private static final String CMD_PROMPT = "cmd"; // command prompt
    private static final String APP_ID = "client_app"; // client app id

    private static final String HELP_FILE = "mslclient_manual.txt";

    private static final String CMD_HELP = "-help";
    private static final String CMD_LIST = "-list";
    private static final String CMD_QUIT = "-quit";

    public enum Status {
        OK(0, "Success"),
        ARG_ERROR(1, "Invalid Arguments"),
        CFG_ERROR(2, "Configuration File Error"),
        CLIENT_CFG_ERROR(3, "Client Configuration Error"),
        CLIENT_EXE_ERROR(4, "Internal Execution Error"),
        SERVER_COMM_ERROR(5, "Server Communication Error"),
        SERVER_APP_ERROR(6, "Server MSL Error Reply");

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

    public static void main(String[] args) {
        if (Arrays.asList(args).contains(CMD_HELP)) {
            help();
            exit(Status.OK);
        }
        if (args.length == 0) {
            System.err.println("Use " + CMD_HELP + " for help");
            exit(Status.ARG_ERROR);
        }

        CmdArguments cmdParam = null;
        try {
            cmdParam = new CmdArguments(args);
        } catch (IllegalCmdArgumentException e) {
            System.err.println(e.getMessage());
            exit(Status.ARG_ERROR);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            exit(Status.CLIENT_EXE_ERROR);
        }
        
        ClientApp clientApp = null;
        try {
            clientApp = new ClientApp(cmdParam);
        } catch (IllegalCmdArgumentException e) {
            System.err.println(e.getMessage());
            exit(Status.ARG_ERROR);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            exit(Status.CLIENT_EXE_ERROR);
        }

        if (cmdParam.isInteractive()) {
            try {
                clientApp.sendMultipleRequests();
                exit(Status.OK);
            } catch (Exception e) {
                System.err.println(e.getMessage());
                exit(Status.CLIENT_EXE_ERROR);
            }
        } else {
            try {
                Status status = clientApp.sendSingleRequest();
                exit(status);
            } catch (IllegalCmdArgumentException e) {
                System.err.println(e.getMessage());
                exit(Status.ARG_ERROR);
            } catch (Exception e) {
                System.err.println(e.getMessage());
                exit(Status.CLIENT_EXE_ERROR);
            }
        }
    }

    private static void exit(final Status status) {
        System.out.println("Exit Status " + status);
        System.exit(status.code);
    }

    private ClientApp(final CmdArguments cmdParam) throws Exception {

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

    private void sendMultipleRequests() throws IOException {
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
                sendSingleRequest();
            } catch (Exception e) {
                System.err.println(e.getMessage());
            }
        }
    }

    /*
     * send single request
     */
    private Status sendSingleRequest() throws Exception {
        Status status = Status.OK;

        // set verbose mode
        if (cmdParam.isVerbose()) {
            appCtx.getMslControl().setFilterFactory(new ConsoleFilterStreamFactory());
        }
        System.out.println("Options: " + cmdParam.getParameters());
        // initialize Client
        final Client client = new Client(appCtx, cmdParam.getEntityId());
        client.setUserAuthenticationDataHandle(new AppUserAuthenticationDataHandle(cmdParam.getUserId(), mslProp));

        // set message mslProperties
        final MessageConfig mcfg = new MessageConfig();
        mcfg.userId = cmdParam.getUserId();
        mcfg.isEncrypted = cmdParam.isEncrypted();
        mcfg.isIntegrityProtected = cmdParam.isIntegrityProtected();
        mcfg.isNonReplayable = cmdParam.isNonReplayable();

        // set key exchange scheme / mechanism
        {
            final String kx = cmdParam.getKeyExchangeScheme();
            if (kx != null) {
                final String kxm = cmdParam.getKeyExchangeMechanism();
                if (KX_AWE.equals(kx)) {
                    if (kxm == null) {
                        throw new IllegalCmdArgumentException("Missing Key Exchange Mechanism");
                    }
                }
                client.setKeyRequestData(kx, kxm);
            }
        }

        // set request payload
        byte[] requestPayload;
        {
            final String inputFile = cmdParam.getPayloadInputFile();
            if (inputFile != null) {
                requestPayload = SharedUtil.readFromFile(inputFile);
            } else {
                requestPayload = cmdParam.getPayloadMessage();
                if (requestPayload == null) {
                    requestPayload = new byte[0];
                }
            }
        }

        final String outputFile = cmdParam.getPayloadOutputFile();

        // send request and process response
        final URL url = cmdParam.getUrl();
        try {
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
                status = Status.SERVER_APP_ERROR;
            } else {
                System.out.println("Response: " + new String(response.getPayload()));
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            throw e;
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
                final Pair<String,String> ep = mslProp.getEmailPassword(userId);
                return new EmailPasswordAuthenticationData(ep.x, ep.y);
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
