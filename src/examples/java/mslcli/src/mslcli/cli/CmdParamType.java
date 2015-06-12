package mslcli.cli;

public enum CmdParamType {
    FLAG {
        @Override
        public void parseFlag(String args) {
            if (args == null) throw new NullPointerException();
            if (!args.trim().isEmpty())
                throw new IllegalArgumentException("Non-Empty FLAG parameter list: " + args);
        }
    },
    LONG {
        @Override
        public long parseLong(String args) {
            if (args == null) throw new NullPointerException();
            return Long.valueOf(args).longValue();
        }
    },
    STRING {
        @Override
        public String parseString(String args) {
            if (args == null) throw new NullPointerException();
            return args.trim();
        }
    },
    STRINGS {
        @Override
        public String parseString(String args) {
            if (args == null) throw new NullPointerException();
            return args.trim();
        }
    },
    FILE {
        @Override
        public String parseString(String args) {
            if (args == null) throw new NullPointerException();
            return args.trim();
        }
    },
    FILES {
        @Override
        public String parseString(String args) {
            if (args == null) throw new NullPointerException();
            return args.trim();
        }
    },
    DIR {
        @Override
        public String parseString(String args) {
            if (args == null) throw new NullPointerException();
            return args.trim();
        }
    };

    public void parseFlag(String args) {
        throw new UnsupportedOperationException("Unsupported Operation for Type " + this);
    }

    public long parseLong(String args) {
        throw new UnsupportedOperationException("Unsupported Operation for Type " + this);
    }

    public String parseString(String args) {
        throw new UnsupportedOperationException("Unsupported Operation for Type " + this);
    }
}
