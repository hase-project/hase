from __future__ import print_function
import code
import types
import inspect
import sys
import tempfile
import re
import shutil
import struct
import fcntl
from bdb import BdbQuit

try:
    import termios
except ImportError:
    termios = None

try:
    import pygments
    import pygments.lexers
    import pygments.formatters
    has_pygments = True
except ImportError:
    has_pygments = False
    pass

BdbQuit_excepthook = None
try:
    import bpython
    has_bpython = True
except ImportError:
    has_bpython = False
    try:
        import IPython
        from IPython.core.debugger import BdbQuit_excepthook
        from IPython.core import page
        from IPython.terminal.ipapp import load_default_config
        from IPython.core.magic import (magics_class, line_magic, Magics)

        ipython_config = load_default_config()
        ipython_config.TerminalInteractiveShell.confirm_exit = False

        old_init = IPython.terminal.embed.InteractiveShellEmbed.__init__

        def new_init(self, *k, **kw):
            frames = kw.pop("frames", None)
            old_init(self, *k, **kw)
            from pry import get_context, highlight, terminal_size

            @magics_class
            class MyMagics(Magics):
                def __init__(self, shell, frames):
                    # You must call the parent constructor
                    super(MyMagics, self).__init__(shell)

                    self.frame_offset = 0
                    self.frames = frames
                    self.calling_frame = frames[0]

                @property
                def active_frame(self):
                    return self.frames[self.frame_offset]

                def build_terminal_list(self, list, term_width=80):
                    line = " "
                    for name in sorted(list):
                        if len(line + name) > term_width:
                            yield line
                            line = " "
                        line += " %s" % name
                    if line != " ":
                        yield line

                @line_magic("ls")
                def ls(self, query):
                    """
                    Show local variables/methods/class properties
                    """
                    lines = []
                    width = terminal_size()[0]

                    methods = []
                    properties = []
                    has_query = True

                    that = self.shell.user_ns.get(query, None)

                    if that is None:
                        that = self.active_frame.locals.get("self", [])
                        has_query = False

                    # apparently there is no better way to check if the caller
                    # is a method
                    for attr in dir(that):
                        try:
                            value = getattr(that, attr)
                        except Exception:
                            continue
                        if isinstance(value, types.MethodType):
                            methods.append(attr)
                        else:
                            properties.append(attr)

                    if len(methods) > 0:
                        lines.append("local methods:")
                        lines.extend(self.build_terminal_list(methods, width))

                    if len(properties) > 0:
                        lines.append("properties")
                        props = self.build_terminal_list(properties, width)
                        lines.extend(props)

                    if not has_query:
                        lines.append("local variables:")
                        local_vars = self.build_terminal_list(
                            self.active_frame.locals.keys(), width)
                        lines.extend(local_vars)

                    page.page("\n".join(lines))

                @line_magic("editfile")
                def editfile(self, query):
                    """
                    open current breakpoint in editor.
                    """
                    self.shell.hooks.editor(
                        self.active_frame.filename,
                        linenum=self.active_frame.lineno)

                @line_magic("where")
                def where(self, query):
                    """
                    Show backtrace
                    """
                    context = []
                    for f in reversed(self.frames[self.frame_offset:]):
                        context.append(get_context(f))
                    page.page("".join(context))

                @line_magic("showsource")
                def showsource(self, query):
                    """
                    Show source of object
                    """
                    obj = self.active_frame.locals.get(
                        query, self.active_frame.globals.get(query, None))
                    if obj is None:
                        return "Not found: %s" % query
                    try:
                        s = inspect.getsource(obj)
                    except TypeError as f:
                        print("%s" % f, file=sys.stderr)
                        return

                    if has_pygments:
                        s = "\n".join(highlight(s.split("\n")))
                    page.page(s)

                def update_context(self):
                    print(get_context(self.active_frame), file=sys.stderr)
                    # hacky
                    scope = self.active_frame.globals.copy()
                    scope.update(self.active_frame.locals)
                    self.shell.user_ns.update(scope)

                @line_magic("up")
                def up(self, query):
                    """
                    Get from call frame up.
                    """
                    self.frame_offset += 1
                    self.frame_offset = min(self.frame_offset,
                                            len(self.frames) - 1)
                    self.update_context()

                @line_magic("down")
                def down(self, query):
                    """
                    Get from call frame down.
                    """
                    self.frame_offset -= 1
                    self.frame_offset = max(self.frame_offset, 0)
                    self.update_context()

                @line_magic("removepry")
                def removepry(self, query):
                    """
                    Remove pry call at current breakpoint.
                    """
                    f = self.calling_frame
                    with open(f.filename) as src, \
                            tempfile.NamedTemporaryFile(mode='w') as dst:
                        for i, line in enumerate(src):
                            if (i + 1) == f.lineno:
                                line = re.sub(r'(import pry;)?\s*pry\(\)', "",
                                              line)
                                if line.strip() == "":
                                    continue
                            dst.write(line)
                        dst.flush()
                        src.close()
                        shutil.copyfile(dst.name, f.filename)

            self.register_magics(MyMagics(self, frames))

        IPython.terminal.embed.InteractiveShellEmbed.__init__ = new_init

        has_ipython = True
    except ImportError:
        has_ipython = False
        pass

try:
    import readline
    has_readline = True
except ImportError:
    has_readline = False
    pass
else:
    import rlcompleter


class Frame():
    """
    Abstraction around old python traceback api
    """

    def __init__(self, *raw_frame):
        self.frame = raw_frame[0]
        self.filename = raw_frame[1]
        self.lineno = raw_frame[2]
        self.function = raw_frame[3]
        self.lines = raw_frame[4]
        self.index = raw_frame[5]
        self.locals = self.frame.f_locals
        self.globals = self.frame.f_globals


class Pry():
    def __init__(self, module):
        self.module = module
        self.lexer = None
        self.formatter = None

    def wrap_raw_frames(self, raw_frames):
        frames = []
        for raw_frame in raw_frames:
            frames.append(Frame(*raw_frame))
        return frames

    def highlight(self, lines):
        if not self.module.has_pygments:
            return lines
        p = self.module.pygments
        if self.lexer is None:
            self.lexer = p.lexers.PythonLexer()
        if self.formatter is None:
            self.formatter = p.formatters.Terminal256Formatter()
        tokens = self.lexer.get_tokens("\n".join(lines))
        source = p.format(tokens, self.formatter)
        return source.split("\n")

    def __enter__(self):
        pass

    def __exit__(self, type, value, tb):
        self.wrap_sys_excepthook()
        if tb is None:
            return
        frames = self.wrap_raw_frames(self.module.inspect.getinnerframes(tb))
        for frame in frames[:-1]:
            print(self.get_context(frame), file=sys.stderr)
        print("%s: %s\n" % (type.__name__, str(value)), file=sys.stderr)
        self(list(reversed(frames)))

    def wrap_sys_excepthook(self):
        m = self.module
        if not m.has_ipython:
            return
        # make sure we wrap it only once or we would end up with a cycle
        #  BdbQuit_excepthook.excepthook_ori == BdbQuit_excepthook
        if m.sys.excepthook != m.BdbQuit_excepthook:
            m.BdbQuit_excepthook.excepthook_ori = m.sys.excepthook
            m.sys.excepthook = m.BdbQuit_excepthook

    def get_context(self, frame, unwind=True):
        before = max(frame.lineno - 6, 0)
        after = frame.lineno + 4
        context = []
        try:
            f = open(frame.filename)

            for i, line in enumerate(f):
                if i >= before:
                    context.append(line.rstrip())
                if i > after:
                    break
            f.close()
        except IOError:
            context = frame.lines
        banner = "From: {} @ line {} :\n".format(frame.filename, frame.lineno)
        i = max(frame.lineno - 5, 0)

        if self.module.has_pygments and not self.module.has_bpython:
            context = self.highlight(context)

        for line in context:
            pointer = "-->" if i == frame.lineno else "   "
            banner += "{} {}: {}\n".format(pointer, i, line)
            i += 1
        return banner

    def fix_tty(self):
        m = self.module
        if m.termios is None:
            return
        # Sometimes when you do something funky, you may lose your terminal
        # echo. This should restore it when spawning new pdb.
        termios_fd = m.sys.stdin.fileno()
        termios_echo = m.termios.tcgetattr(termios_fd)
        termios_echo[3] = termios_echo[3] | m.termios.ECHO
        m.termios.tcsetattr(termios_fd, termios.TCSADRAIN, termios_echo)

    def terminal_size(self):
        m = self.module
        if m.termios is None:
            return 80, 24
        args = m.struct.pack('HHHH', 0, 0, 0, 0)
        res = m.fcntl.ioctl(0, m.termios.TIOCGWINSZ, args)
        h, w, hp, wp = m.struct.unpack('HHHH', res)
        return w, h

    def shell(self, context, frames):
        active_frame = frames[0]
        m = self.module
        if m.has_bpython:
            globals().update(active_frame.globals)
            m.bpython.embed(active_frame.locals.copy(), banner=context)
        if m.has_ipython:
            shell = m.IPython.terminal.embed.InteractiveShellEmbed(config=m.ipython_config, frames=frames)
            scope = active_frame.globals.copy()
            scope.update(active_frame.locals)
            print(context.rstrip())
            shell.mainloop(local_ns=scope)
        else:
            if m.has_readline:
                m.readline.parse_and_bind("tab: complete")
            globals().update(active_frame.globals)
            m.code.interact(context, local=active_frame.locals.copy())

    def __call__(self, frames=None):
        if frames is None:
            frames = self.module.inspect.getouterframes(
                self.module.inspect.currentframe())
            frames = self.wrap_raw_frames(frames)
            if len(frames) > 1:
                frames = frames[1:]

        context = self.get_context(frames[0])
        self.fix_tty()
        self.shell(context, frames)


# hack for convenient access
sys.modules[__name__] = Pry(sys.modules[__name__])
