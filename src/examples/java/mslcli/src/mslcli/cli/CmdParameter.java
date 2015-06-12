package mslcli.cli;

public class CmdParameter {
    public CmdOption getOption() {
        return opt;
    }

    public CmdParamType getType() {
        return opt.getType();
    }

    public long getLong() {
        checkType(CmdParamType.LONG);
        return l;
    }

    public String getString() {
        checkType(CmdParamType.STRING);
        return s;
    }

    public String[] getStrings() {
        checkType(CmdParamType.STRINGS);
        return ss;
    }

    public String getFile() {
        checkType(CmdParamType.FILE);
        return s;
    }

    public String[] getFiles() {
        checkType(CmdParamType.FILES);
        return ss;
    }

    public String getDir() {
        checkType(CmdParamType.DIR);
        return s;
    }

    private void checkType(CmdParamType type) {
        if (this.opt.getType() != type) {
            throw new IllegalArgumentException(
                String.format("Type Mismatch %s for parameter %s", opt.getType(), opt.getName()));
        }
    }

    private CmdParameter(CmdOption opt) {
        this.opt = opt;
    }

    public void parse(String args) {
        switch (opt.getType()) {
            case FLAG:
                opt.getType().parseFlag(args);
                break;
            case LONG:
                l = opt.getType().parseLong(args);
                break;
            case STRING:
                s = opt.getType().parseString(args);
                break;
            case STRINGS:
                ss = opt.getType().parseString(args).split(",");
                break;
            case FILE:
                s = opt.getType().parseString(args);
                break;
            case FILES:
                ss = opt.getType().parseString(args).split(",");
                break;
            case DIR:
                s = opt.getType().parseString(args);
                break;
            default:
                throw new IllegalArgumentException(
                    String.format("Invalid %s parameter(s): %s %s", opt.getType(), opt.getName(), args));
        }
    }

    private final CmdOption opt;
    private long l = 0L;
    private String s = null;
    private String[] ss = null;
}
