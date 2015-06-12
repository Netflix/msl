package mslcli.cli;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public enum CmdOption {
    DB                   ("-db"  , CmdParamType.DIR   ),
    CONFIG               ("-cfg" , CmdParamType.FILE  ),
    INTERACTIVE          ("-i"   , CmdParamType.FLAG  ),
    PAYLOAD_FILE         ("-pf"  , CmdParamType.FILE  ),
    ENTITY_AUTH_SCHEME   ("-ea"  , CmdParamType.STRING),
    ENTITY_AUTH_DATA_FILE("-eadf", CmdParamType.FILE  ),
    MTOKEN_FILE          ("-mtf" , CmdParamType.FILE  ),
    USER_AUTH_SCHEME     ("-ua"  , CmdParamType.STRING),
    USER_AUTH_DATA_FILE  ("-uadf", CmdParamType.FILE  ),
    USER_ID_TOKEN_FILE   ("-uitf", CmdParamType.FILE  ),
    KEY_EXCHANGE         ("-x"   , CmdParamType.STRING),
    SERVICE_TOKEN_FILES  ("-stf" , CmdParamType.FILES ),
    SENDER               ("-snd" , CmdParamType.STRING),
    RECIPIENT            ("-rcp" , CmdParamType.STRING),
    NON_REPLAYABLE       ("-nr"  , CmdParamType.FLAG  ),
    RENEWABLE            ("-rn"  , CmdParamType.FLAG  ),
    MESSAGE_ID           ("-mid" , CmdParamType.LONG  ),
    URL                  ("-url" , CmdParamType.STRING);

    private static final Map<String,CmdOption> options = new HashMap<String,CmdOption>();
    static {
        for (CmdOption opt : values()) {
            options.put(opt.getName(), opt);
        }
    }

    public static CmdOption getOption(final String name) {
        return options.get(name);
    }

    public static Set<String> getNames() {
        return options.keySet();
    }

    private final String name;
    private final CmdParamType type;

    public String getName() {
        return name;
    }

    public CmdParamType getType() {
        return type;
    }

    private CmdOption(final String name, final CmdParamType type) {
        this.name = name;
        this.type = type;
    }
}
