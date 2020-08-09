# python 2 and 3
from __future__ import print_function

import math
import string
import operator
from functools import reduce

# Python 2 and 3: zip_longest
from six import StringIO

try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest


def indent(
    rows,
    hasHeader=False,
    headerChar="-",
    delim=" | ",
    justify="left",
    separateRows=False,
    prefix="",
    postfix="",
    wrapfunc=lambda x: x,
):
    """
    @author http://code.activestate.com/recipes/267662-table-indentation/

    Indents a table by column.
    - rows: A sequence of sequences of items, one sequence per row.
    - hasHeader: True if the first row consists of the columns' names.
    - headerChar: Character to be used for the row separator line
        (if hasHeader==True or separateRows==True).
    - delim: The column delimiter.
    - justify: Determines how are data justified in their column.
        Valid values are 'left','right' and 'center'.
    - separateRows: True if rows are to be separated by a line
        of 'headerChar's.
    - prefix: A string prepended to each printed row.
    - postfix: A string appended to each printed row.
    - wrapfunc: A function f(text) for wrapping text; each element in
        the table is first wrapped by this function."""
    # closure for breaking logical rows to physical, using wrapfunc
    def rowWrapper(row):
        newRows = [wrapfunc(item).split("\n") for item in row]
        return [[substr or "" for substr in item] for item in zip_longest(*newRows)]

    # break each logical row into one or more physical ones
    logicalRows = [rowWrapper(row) for row in rows]
    # columns of physical rows
    columns = zip_longest(*reduce(operator.add, logicalRows))
    # get the maximum of each column by the string length of its items
    maxWidths = [max([len(str(item)) for item in column]) for column in columns]
    rowSeparator = headerChar * (
        len(prefix) + len(postfix) + sum(maxWidths) + len(delim) * (len(maxWidths) - 1)
    )
    # select the appropriate justify method
    justify = {"center": str.center, "right": str.rjust, "left": str.ljust}[
        justify.lower()
    ]
    output = StringIO()
    if separateRows:
        print(rowSeparator, file=output)
    for physicalRows in logicalRows:
        for row in physicalRows:
            print(
                prefix
                + delim.join(
                    [justify(str(item), width) for (item, width) in zip(row, maxWidths)]
                )
                + postfix,
                file=output,
            )
        if separateRows or hasHeader:
            print(rowSeparator, file=output)
            hasHeader = False
    return output.getvalue()


def wrap_always(text, width):
    """A simple word-wrap function that wraps text on exactly width characters.
    It doesn't split the text in words."""
    return "\n".join(
        [
            text[width * i : width * (i + 1)]
            for i in range(int(math.ceil(1.0 * len(text) / width)))
        ]
    )


def wrap_always_list(alltext, width):
    text_list = []
    for text in alltext.splitlines():
        for subtext in [
            text[width * i : width * (i + 1)]
            for i in range(int(math.ceil(1.0 * len(text) / width)))
        ]:
            text_list.append(
                "".join([char if char in string.printable else "." for char in subtext])
            )
    return text_list


def table_print(rows, width=80):
    print(
        indent(
            rows,
            hasHeader=True,
            separateRows=False,
            prefix="  ",
            postfix="  ",
            wrapfunc=lambda x: wrap_always(x, width),
        )
    )


def getTerminalSize():
    # http://stackoverflow.com/questions/566746/how-to-get-console-window-width-in-python
    import platform

    current_os = platform.system()
    tuple_xy = None
    if current_os == "Windows":
        tuple_xy = _getTerminalSize_windows()
        if tuple_xy is None:
            tuple_xy = _getTerminalSize_tput()
    # needed for window's python in cygwin's xterm!
    if (
        current_os == "Linux"
        or current_os == "Darwin"
        or current_os.startswith("CYGWIN")
    ):
        tuple_xy = _getTerminalSize_linux()
    if tuple_xy is None:
        print("default")
        tuple_xy = (80, 25)  # default value

    return tuple_xy


def _getTerminalSize_windows():
    res = None
    try:
        from ctypes import windll, create_string_buffer

        # stdin handle is -10
        # stdout handle is -11
        # stderr handle is -12

        h = windll.kernel32.GetStdHandle(-12)
        csbi = create_string_buffer(22)
        res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
    except Exception:
        return None
    if res:
        import struct

        (
            bufx,
            bufy,
            curx,
            cury,
            wattr,
            left,
            top,
            right,
            bottom,
            maxx,
            maxy,
        ) = struct.unpack("hhhhHhhhhhh", csbi.raw)
        sizex = right - left + 1
        sizey = bottom - top + 1
        return sizex, sizey
    else:
        return None


def _getTerminalSize_tput():
    # get terminal width
    # src: http://stackoverflow.com/questions/263890/how-do-i-find-the-width-height-of-a-terminal-window
    try:
        import subprocess

        proc = subprocess.Popen(
            ["tput", "cols"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )
        output = proc.communicate(input=None)
        cols = int(output[0])
        proc = subprocess.Popen(
            ["tput", "lines"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )
        output = proc.communicate(input=None)
        rows = int(output[0])
        return (cols, rows)
    except Exception:
        return None


def _getTerminalSize_linux():
    import fcntl
    import termios
    import struct
    import os

    def ioctl_GWINSZ(fd):
        try:
            cr = struct.unpack("hh", fcntl.ioctl(fd, termios.TIOCGWINSZ, "1234"))
        except Exception:
            return None
        return cr

    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except Exception:
            pass
    if not cr:
        try:
            cr = (os.environ.get("LINES"), os.environ.get("COLUMNS"))
        except Exception:
            return None
    if not cr[0]:
        return None
    return int(cr[1]), int(cr[0])
