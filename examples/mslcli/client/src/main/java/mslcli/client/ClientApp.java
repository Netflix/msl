/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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
import java.io.InputStream;
import java.net.ConnectException;
import java.security.Security;
import java.util.concurrent.ExecutionException;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.IllegalCmdArgumentRuntimeException;
import mslcli.common.Triplet;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.ConfigurationRuntimeException;
import mslcli.common.util.MslProperties;
import mslcli.common.util.SharedUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslException;
import com.netflix.msl.msg.ConsoleFilterStreamFactory;

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

    /** interactive prompt for setting/changing runtime arguments */
    private static final String CMD_PROMPT = "args";
    /** MSL CLI client manual file name */
    private static final String HELP_FILE = "mslclient_manual.txt";

    /** interactive command to print help */
    private static final String CMD_HELP = "help";
    /** interactive command to list current runtime arguments */
    private static final String CMD_LIST = "list";
    /** interactive command to save MSL store */
    private static final String CMD_SAVE = "save";
    /** interactive command to exit MSL CLI client program */
    private static final String CMD_QUIT = "quit";
    /** interactive command to print the list of interactive commands */
    private static final String CMD_HINT = "?";

    /**
     * enumeration of status codes returned by MSL CLI program
     */
    public enum Status {
        /** success status */
        OK(0, "Success"),
        /** invalid command line arguments */
        ARG_ERROR    (1, "Invalid Arguments"),
        /** invalid configuration file */
        CFG_ERROR    (2, "Configuration File Error"),
        /** exception from the MSL stack */
        MSL_EXC_ERROR(3, "MSL Exception"),
        /** MSL protocol error from the server */
        MSL_ERROR    (4, "Server MSL Error Reply"),
        /** problem connecting/talking to the server */
        COMM_ERROR   (5, "Server Communication Error"),
        /** internal exception */
        EXE_ERROR    (6, "Internal Execution Error");

        /** exit status code */
        private final int code;
        /** exit status code explanation */
        private final String info;

        /**
         * @param code status code
         * @param info status code explanation
         */
        Status(final int code, final String info) {
            this.code = code;
            this.info = info;
        }

        @Override
        public String toString() {
            return String.format("%d: %s", code, info);
        }
    }

    /** runtime arguments */
    private final CmdArguments cmdParam;
    /** application context */
    private final AppContext appCtx;
    /** client bound to the given entity identity */
    private Client client;
    /** console filter stream factory for logging */
    private final ConsoleFilterStreamFactory consoleFilterStreamFactory;

    /**
     * Launcher of MSL CLI client. See user manual in HELP_FILE.
     * @param args command line arguments
     */
    public static void main(final String[] args) {
        Status status = Status.OK;
        try {
            if (args.length == 0) {
                err("Use " + CMD_HELP + " for help");
                status = Status.ARG_ERROR;
            } else if (CMD_HELP.equalsIgnoreCase(args[0])) {
                help();
                status = Status.OK;
            } else {
                final CmdArguments cmdParam = new CmdArguments(args);
                final ClientApp clientApp = new ClientApp(cmdParam);
                if (cmdParam.isInteractive()) {
                    clientApp.sendInteractive();
                    status = Status.OK;
                } else {
                    status = clientApp.sendRequest(null);
                }
                clientApp.shutdown();
            }
        } catch (final ConfigurationException e) {
            err(e.getMessage());
            status = Status.CFG_ERROR;
        } catch (final IllegalCmdArgumentException e) {
            err(e.getMessage());
            status = Status.ARG_ERROR;
        } catch (final IOException e) {
            err(e.getMessage());
            status = Status.EXE_ERROR;
            SharedUtil.getRootCause(e).printStackTrace(System.err);
        } catch (final RuntimeException e) {
            err(e.getMessage());
            status = Status.EXE_ERROR;
            SharedUtil.getRootCause(e).printStackTrace(System.err);
        }
        out("Exit Status " + status);
        System.exit(status.code);
    }

    /**
     * ClientApp holds the instance of one Client and some other objects which are global for the application.
     * Instance of Client is supposed to be re-instantiated only when its entity identity changes,
     * which is only applicable in the interactive mode. Changing entity identity within a given Client
     * instance would be too convoluted; it makes sense to permanently bind Client with its entity ID.
     *
     * @param cmdParam encapsulation of command-line arguments
     * @throws ConfigurationException if some configuration parameters required for initialization are missing, invalid, or mutually inconsistent
     * @throws IllegalCmdArgumentException if some command line arguments required for initialization are missing, invalid, or mutually inconsistent
     * @throws IOException if configuration file reading failed
     */
    public ClientApp(final CmdArguments cmdParam) throws ConfigurationException, IllegalCmdArgumentException, IOException {
        if (cmdParam == null) {
            throw new IllegalArgumentException("NULL Arguments");
        }

        // save command-line arguments
        this.cmdParam = cmdParam;

        // load configuration from the configuration file
        final MslProperties mslProp = MslProperties.getInstance(SharedUtil.loadPropertiesFromFile(cmdParam.getConfigFilePath()));

        // load PSK if specified
        final String pskFile = cmdParam.getPskFile();
        if (pskFile != null) {
            final Triplet<String,String,String> pskEntry;
            try {
                pskEntry = SharedUtil.readPskFile(pskFile);
            } catch (final IOException e) {
                throw new ConfigurationException(e.getMessage());
            }
            cmdParam.merge(new CmdArguments(new String[] { CmdArguments.P_EID, pskEntry.x }));
            mslProp.addPresharedKeys(pskEntry);
        }

        // load MGK if specified
        final String mgkFile = cmdParam.getMgkFile();
        if (mgkFile != null) {
            final Triplet<String,String,String> mgkEntry;
            try {
                mgkEntry = SharedUtil.readPskFile(mgkFile);
            } catch (final IOException e) {
                throw new ConfigurationException(e.getMessage());
            }
            cmdParam.merge(new CmdArguments(new String[] { CmdArguments.P_EID, mgkEntry.x }));
            mslProp.addMgkKeys(mgkEntry);
        }

        // initialize application context
        this.appCtx = AppContext.getInstance(mslProp);

        // initialize console steram factory for logging
        this.consoleFilterStreamFactory = new ConsoleFilterStreamFactory();
    }

    /**
     * In a loop as a user to modify command-line arguments and then send a single request,
     * until a user enters "quit" command.
     *
     * @throws IllegalCmdArgumentException invalid / inconsistent command line arguments
     * @throws IOException in case of user input reading error
     */

    public void sendInteractive() throws IllegalCmdArgumentException, IOException {
        while (true) {
            final String options = SharedUtil.readInput(CMD_PROMPT);
            if (optMatch(CMD_QUIT, options)) {
                return;
            }
            if (optMatch(CMD_HELP, options)) {
                help();
                continue;
            }
            if (optMatch(CMD_LIST, options)) {
                if (client != null) {
                    out(client.getConfigInfo());
                } else {
                    err(cmdParam.getParameters());
                }
                continue;
            }
            if (optMatch(CMD_SAVE, options)) {
                if (client != null)
                    client.saveMslStore();
                continue;
            }
            if (optMatch(CMD_HINT, options)) {
                hint();
                continue;
            }
            try {
                // parse entered parameters just  like command-line arguments
                final CmdArguments p;
                if (options != null && !options.trim().isEmpty()) {
                    p = new CmdArguments(SharedUtil.split(options));
                } else {
                    p = null;
                }
                final Status status = sendRequest(p);
                if (status != Status.OK) {
                    out("Status: " + status.toString());
                }
            } catch (final IllegalCmdArgumentException e) {
                err(e.getMessage());
            } catch (final RuntimeException e) {
                err(e.getMessage());
            }
        }
    }

    /**
     * @param option option to be selected
     * @param val user entry
     * @return true if user entry is the beginning of the option string
     */
    private static boolean optMatch(final String option, final String val) {
        return (option != null) && (val != null) && (val.trim().length() != 0) && option.startsWith(val.trim());
    }

    /**
     * send single request
     *
     * @param args additional command-line arguments specified in interactive mode (null in non-interactive mode)
     * @return Status containing either reply payload or MSL error
     */
    public Status sendRequest(final CmdArguments args) {
        Status status = Status.OK;

        try_label: try {
            CmdArguments currentCmdParam = (client != null) ? client.getConfig() : cmdParam;

            // set verbose mode
            if (currentCmdParam.isVerbose()) {
                appCtx.getMslControl().setFilterFactory(consoleFilterStreamFactory);
            } else {
                appCtx.getMslControl().setFilterFactory(null);
            }

            // (re)initialize Client for the first time or whenever entity identity changes
            if ((client == null) || ((args != null) && (args.getOptEntityId() != null) && !client.getEntityId().equals(args.getOptEntityId()))) {
                out("New Client");
                // update current args
                if (args != null)
                    currentCmdParam.merge(args);
                if (client != null) {
                    client.saveMslStore();
                    client = null; // required for keeping the state, in case the next line throws exception
                }
                // create new client
                client = new Client(appCtx, currentCmdParam);
            } else if (args != null) {
                currentCmdParam = client.modifyConfig(args);
            }

            // set request payload
            byte[] requestPayload = null;
            final String inputFile = currentCmdParam.getPayloadInputFile();
            requestPayload = currentCmdParam.getPayloadMessage();
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

            /* See if the output file for response payload is specified.
             * If it is, it must either exist or be creatable.
             */
            final String outputFile = currentCmdParam.getPayloadOutputFile();

            /* ********************************************
             * FINALLY: SEND REQUEST AND PROCESS RESPONSE *
             **********************************************/
            final int nsend = client.getConfig().getNumSends();
            int count;
            final long t_start = System.currentTimeMillis();
            for (count = 0; count < nsend; count++) {
                final Client.Response response = client.sendRequest(requestPayload);

                // Non-NULL response payload - good
                if (response.getPayload() != null) {
                    if (count == 0) {
                        if (outputFile != null) {
                            SharedUtil.saveToFile(outputFile, response.getPayload(), false /*overwrite*/);
                        } else {
                            out("Response: " + new String(response.getPayload(), MslConstants.DEFAULT_CHARSET));
                        }
                    }
                    status = Status.OK;
                // NULL payload, must be MSL error response
                } else if (response.getErrorHeader() != null) {
                    if (response.getErrorHeader().getErrorMessage() != null) {
                        err(String.format("MSL RESPONSE ERROR: error_code %d, error_msg \"%s\"",
                            response.getErrorHeader().getErrorCode().intValue(),
                            response.getErrorHeader().getErrorMessage()));
                    } else {
                        err(String.format("ERROR: %s" + response.getErrorHeader()));
                    }
                    status = Status.MSL_ERROR;
                // NULL payload, NULL error header - should never happen
                } else {
                    out("Response with no payload or error header ???");
                    status = Status.MSL_ERROR;
                }
            }
            final long t_total = System.currentTimeMillis() - t_start;
            if (count != 0) {
                out(String.format("Messages Sent: %d, Total Time: %d msec, Per Message: %d msec", count, t_total, t_total/count));
            }
        } catch (final MslException e) {
            err(SharedUtil.getMslExceptionInfo(e));
            status = Status.MSL_EXC_ERROR;
            SharedUtil.getRootCause(e).printStackTrace(System.err);
        } catch (final ConfigurationException e) {
            err("Error: " + e.getMessage());
            status = Status.CFG_ERROR;
        } catch (final ConfigurationRuntimeException e) {
            err("Error: " + e.getCause().getMessage());
            status = Status.CFG_ERROR;
        } catch (final IllegalCmdArgumentException e) {
            err("Error: " + e.getMessage());
            status = Status.ARG_ERROR;
        } catch (final IllegalCmdArgumentRuntimeException e) {
            err("Error: " + e.getCause().getMessage());
            status = Status.ARG_ERROR;
        } catch (final ConnectException e) {
            err("Error: " + e.getMessage());
            status = Status.COMM_ERROR;
        } catch (final ExecutionException e) {
            final Throwable thr = SharedUtil.getRootCause(e);
            if (thr instanceof ConfigurationException) {
                err("Error: " + thr.getMessage());
                status = Status.CFG_ERROR;
            } else if (thr instanceof IllegalCmdArgumentException) {
                err("Error: " + thr.getMessage());
                status = Status.ARG_ERROR;
            } else if (thr instanceof MslException) {
                err(SharedUtil.getMslExceptionInfo((MslException)thr));
                status = Status.MSL_EXC_ERROR;
                SharedUtil.getRootCause(e).printStackTrace(System.err);
            } else if (thr instanceof ConnectException) {
                err("Error: " + thr.getMessage());
                status = Status.COMM_ERROR;
            } else {
                err("Error: " + thr.getMessage());
                thr.printStackTrace(System.err);
                status = Status.EXE_ERROR;
            }
        } catch (final IOException e) {
            err("Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            status = Status.EXE_ERROR;
        } catch (final InterruptedException e) {
            err("Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            status = Status.EXE_ERROR;
        } catch (final RuntimeException e) {
            err("Error: " + e.getMessage());
            SharedUtil.getRootCause(e).printStackTrace(System.err);
            status = Status.EXE_ERROR;
        }

        return status;
    }

    /**
     * shutdown activities
     * @throws IOException if cannot save MSL store
     */
    public void shutdown() throws IOException {
        if (client != null)
            client.saveMslStore();
    }

    /**
     * helper - print help file
     */
    private static void help() {
        InputStream input = null;
        try {
            input = ClientApp.class.getResourceAsStream(HELP_FILE);
            final String helpInfo = new String(SharedUtil.readIntoArray(input), MslConstants.DEFAULT_CHARSET);
            out(helpInfo);
        } catch (final Exception e) {
            err(String.format("Cannot read help file %s: %s", HELP_FILE, e.getMessage()));
        } finally {
            if (input != null) try { input.close(); } catch (final Exception ignore) {}
        }
    }

    /**
     * helper - interactive mode hint
     */
    private static void hint() {
        out("Choices:");
        out("a) Modify Command-line arguments, if any need to be modified, and press Enter to send a message.");
        out("   Use exactly the same syntax as from the command line.");
        out(String.format("b) Type \"%s\" for listing currently selected command-line arguments.", CMD_LIST));
        out(String.format("c) Type \"%s\" for the detailed instructions on using this tool.", CMD_HELP));
        out(String.format("d) Type \"%s\" to save MSL store to the disk. MSL store is saved automatically on exit.", CMD_SAVE));
        out(String.format("e) Type \"%s\" to quit this tool.", CMD_QUIT));
    }

    /**
     * @param msg message to log
     */
    private static void out(final String msg) {
        System.out.println(msg);
    }

    /**
     * @param msg message to log
     */
    private static void err(final String msg) {
        System.err.println(msg);
    }
}
