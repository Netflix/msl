package burp;

import burp.msl.WiretapException;

import java.awt.*;

/**
 * User: skommidi
 * Date: 9/25/14
 */
public class MSLTab implements IMessageEditorTab {

    public MSLTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.editable = editable;
        this.callbacks = callbacks;
        this.helpers = helpers;

        // create an instance of Burp's text editor
        txtInput = callbacks.createTextEditor();
        txtInput.setEditable(editable);

        this.mslHttpListener = new MSLHttpListener(this.callbacks, this.helpers);
    }

    @Override
    public String getTabCaption() {
        return "MSL Parse";
    }

    @Override
    public Component getUiComponent() {
        return txtInput.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return true;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if(content == null) {
            // clear our display
            txtInput.setText(null);
            txtInput.setEditable(false);
        } else {
            // TODO: fix setText
            String data = null;
            String body = mslHttpListener.getBody(content);
            try {
                data = mslHttpListener.processMslMessage(body);
            } catch (WiretapException e) {
                throw new RuntimeException(e.getMessage(), e);
            }
            txtInput.setText(data.getBytes());
            txtInput.setEditable(editable);
        }

        // remember the displayed content
        currentMessage = content;
    }

    @Override
    public byte[] getMessage() {
        // determine whether the user modified the deserialized data
        if (txtInput.isTextModified()) {
            // reserialize the data
            // TODO: fix the reserialization part
            return currentMessage;
        } else
            return currentMessage;
    }

    @Override
    public boolean isModified() {
        return txtInput.isTextModified();
    }

    @Override
    public byte[] getSelectedData() {
        return txtInput.getSelectedText();
    }

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final boolean editable;
    private final MSLHttpListener mslHttpListener;

    private ITextEditor txtInput;
    private byte[] currentMessage;
}
