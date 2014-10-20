package burp;

/**
 * User: skommidi
 * Date: 9/25/14
 */
public class MSLTabFactory implements IMessageEditorTabFactory {

    public MSLTabFactory(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        MSLTab mslTab = new MSLTab(controller, editable, callbacks, helpers);
        return mslTab;
    }

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
}
