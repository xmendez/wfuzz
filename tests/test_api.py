import unittest
import sys
from io import BytesIO
import gzip
import pickle as pickle

import wfuzz
from wfuzz.facade import Facade
from wfuzz.fuzzobjects import FuzzResult
from wfuzz.fuzzrequest import FuzzRequest

try:
    # Python >= 3.3
    from unittest import mock
except ImportError:
    # Python < 3.3
    import mock


class APITests(unittest.TestCase):
    def test_payload_description(self):
        class mock_saved_session(object):
            def __init__(self, fields, show_field):
                fr = FuzzRequest()
                fr.url = "http://www.wfuzz.org/path?param=1&param2=2"
                fuzz_res = FuzzResult(history=fr)
                fuzz_res._fields = fields
                fuzz_res._show_field = show_field

                self.outfile = BytesIO()

                with gzip.GzipFile(fileobj=self.outfile, mode="wb") as f:
                    pickle.dump(fuzz_res, f)

                self.outfile.seek(0)
                self.outfile.name = "mockfile"

            def close(self):
                pass

            def read(self, *args, **kwargs):
                return self.outfile.read(*args, **kwargs)

            def seek(self, *args, **kwargs):
                return self.outfile.seek(*args, **kwargs)

            def tell(self):
                return self.outfile.tell()

        # load plugins before mocking file object
        Facade().payloads

        m = mock.MagicMock(name="open", spec=open)
        m.return_value = mock_saved_session(["r.params.all"], True)

        mocked_fun = (
            "builtins.open" if sys.version_info >= (3, 0) else "__builtin__.open"
        )
        with mock.patch(mocked_fun, m):
            payload_list = list(
                wfuzz.payload(
                    **{
                        "show_field": True,
                        "fields": ["r"],
                        "payloads": [
                            ("wfuzzp", {"default": "mockedfile", "encoder": None}, None)
                        ],
                    }
                )
            )
            self.assertEqual(
                sorted(
                    "-".join([res[0].description for res in payload_list]).split("\n")
                ),
                sorted(["param=1", "param2=2"]),
            )

        m = mock.MagicMock(name="open", spec=open)
        m.return_value = mock_saved_session(["url"], None)

        mocked_fun = (
            "builtins.open" if sys.version_info >= (3, 0) else "__builtin__.open"
        )
        with mock.patch(mocked_fun, m):
            payload_list = list(
                wfuzz.payload(
                    **{
                        "show_field": True,
                        "fields": ["r"],
                        "payloads": [
                            ("wfuzzp", {"default": "mockedfile", "encoder": None}, None)
                        ],
                    }
                )
            )
            self.assertEqual(
                [res[0].description for res in payload_list],
                ["http://www.wfuzz.org/path?param=1&param2=2"],
            )

        m = mock.MagicMock(name="open", spec=open)
        m.return_value = mock_saved_session(["r.scheme"], False)

        mocked_fun = (
            "builtins.open" if sys.version_info >= (3, 0) else "__builtin__.open"
        )
        with mock.patch(mocked_fun, m):
            payload_list = list(
                wfuzz.payload(
                    **{
                        "show_field": True,
                        "fields": ["r"],
                        "payloads": [
                            ("wfuzzp", {"default": "mockedfile", "encoder": None}, None)
                        ],
                    }
                )
            )
            self.assertEqual(
                [res[0].description for res in payload_list],
                ["http://www.wfuzz.org/path?param=1&param2=2 | http"],
            )

    def test_payload(self):
        with mock.patch("os.walk") as mocked_oswalk:
            mocked_oswalk.return_value = [
                ("foo", ("bar",), ("baz",)),
                ("foo/bar", (), ("spam", "eggs")),
            ]
            payload_list = list(
                wfuzz.payload(
                    **{
                        "payloads": [
                            ("dirwalk", {"default": "foo", "encoder": None}, None)
                        ]
                    }
                )
            )
            self.assertEqual(
                sorted(payload_list), sorted([("baz",), ("bar/spam",), ("bar/eggs",)])
            )

        class mock_file(object):
            def __init__(self):
                self.my_iter = iter([b"one", b"two"])

            def __iter__(self):
                return self

            def __next__(self):
                return next(self.my_iter)

            def seek(self, pos):
                self.my_iter = iter([b"one", b"two"])

            next = __next__  # for Python 2

        m = mock.MagicMock(name="open", spec=open)
        m.return_value = mock_file()

        mocked_fun = (
            "builtins.open" if sys.version_info >= (3, 0) else "__builtin__.open"
        )
        with mock.patch(mocked_fun, m):
            payload_list = list(
                wfuzz.payload(
                    **{
                        "payloads": [
                            ("file", {"default": "mockedfile", "encoder": None}, None)
                        ]
                    }
                )
            )
            self.assertEqual(sorted(payload_list), sorted([("one",), ("two",)]))
