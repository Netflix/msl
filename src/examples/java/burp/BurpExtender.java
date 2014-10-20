package burp;

import java.io.PrintWriter;

/**
 * User: skommidi
 * Date: 9/10/14
 */
public class BurpExtender implements IBurpExtender {

    /**
     * Implement {@link IBurpExtender}
     *
     * @param callbacks
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // set our extension name
        callbacks.setExtensionName("MSL extension");

        // obtain callbacks object
        this.callbacks = callbacks;
        callbacks.issueAlert("Hello There!!!");

        // obtain an extension helpers object
        this.helpers = callbacks.getHelpers();

        // registering MSL Tab factory
        callbacks.registerMessageEditorTabFactory(new MSLTabFactory(this.callbacks, this.helpers));

        // registering http listener
        callbacks.registerHttpListener(new MSLHttpListener(this.callbacks, this.helpers));

        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

    }


    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;
}
