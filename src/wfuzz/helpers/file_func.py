import os
import sys
import re
import pkg_resources

from chardet.universaldetector import UniversalDetector
import chardet

from ..exception import FuzzExceptInternalError


def get_filter_help_file():
    FILTER_HELP_FILE = "advanced.rst"
    FILTER_HELP_DEV_FILE = "../../../docs/user/advanced.rst"

    filter_help_text = None
    try:
        fname = pkg_resources.resource_filename("wfuzz", FILTER_HELP_FILE)
        filter_help_text = open(fname).read()
    except IOError:
        filter_help_text = open(get_path(FILTER_HELP_DEV_FILE)).read()

    return filter_help_text


def get_home(check=False, directory=None):
    path = os.path.join(os.path.expanduser("~"), ".wfuzz")
    if check:
        if not os.path.exists(path):
            os.makedirs(path)

    return os.path.join(path, directory) if directory else path


def get_path(directory=None):
    abspath = os.path.abspath(__file__)
    ret = os.path.dirname(abspath)

    return os.path.join(ret, directory) if directory else ret


def find_file_in_paths(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)

    return None


class FileDetOpener:
    typical_encodings = [
        "UTF-8",
        "ISO-8859-1",
        "Windows-1251",
        "Shift JIS",
        "Windows-1252",
        "GB2312",
        "EUC-KR",
        "EUC-JP",
        "GBK",
        "ISO-8859-2",
        "Windows-1250",
        "ISO-8859-15",
        "Windows-1256",
        "ISO-8859-9",
        "Big5",
        "Windows-1254",
    ]

    def __init__(self, file_path, encoding=None):
        self.cache = []
        self.file_des = open(file_path, mode="rb")
        self.det_encoding = encoding
        self.encoding_forced = False

    def close(self):
        self.file_des.close()

    def reset(self):
        self.file_des.seek(0)

    def __iter__(self):
        return self

    def __next__(self):
        decoded_line = None
        line = None
        last_error = None

        while decoded_line is None:

            while self.det_encoding is None:
                detect_encoding = self.detect_encoding().get("encoding", "utf-8")
                self.det_encoding = (
                    detect_encoding if detect_encoding is not None else "utf-8"
                )

            if line is None:
                if self.cache:
                    line = self.cache.pop()
                else:
                    line = next(self.file_des)
                    if not line:
                        raise StopIteration

            try:
                decoded_line = line.decode(self.det_encoding)
            except UnicodeDecodeError:
                if last_error is not None and last_error:
                    self.det_encoding = last_error.pop()
                elif last_error is None and not self.encoding_forced:
                    last_error = list(reversed(self.typical_encodings))
                    last_error.append(chardet.detect(line).get("encoding"))
                elif not last_error:
                    raise FuzzExceptInternalError("Unable to decode wordlist file!")

                decoded_line = None

        return decoded_line

    def detect_encoding(self):
        detector = UniversalDetector()
        detector.reset()

        for line in self.file_des:
            detector.feed(line)
            self.cache.append(line)
            if detector.done:
                break

        detector.close()

        return detector.result

    next = __next__  # for Python 2


def open_file_detect_encoding(file_path):
    def detect_encoding(file_path):
        detector = UniversalDetector()
        detector.reset()

        with open(file_path, mode="rb") as file_to_detect:
            for line in file_to_detect:
                detector.feed(line)
                if detector.done:
                    break
        detector.close()

        return detector.result

    if sys.version_info >= (3, 0):
        return open(
            file_path, "r", encoding=detect_encoding(file_path).get("encoding", "utf-8")
        )
    else:
        return open(file_path, "r")
