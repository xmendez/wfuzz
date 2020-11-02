import pytest
import os
import tempfile

import wfuzz


def get_temp_file():
    temp_name = next(tempfile._get_candidate_names())
    defult_tmp_dir = tempfile._get_default_tempdir()

    return os.path.join(defult_tmp_dir, temp_name)


def test_filter_prev_payload():

    filename = get_temp_file()
    for res in wfuzz.get_session(
        "-z range --zD 0-0 -H test:1 -u http://localhost:9000/anything/FUZZ"
    ).fuzz(save=filename):
        pass

    filename_new = get_temp_file()
    for res in wfuzz.get_session(
        "-z wfuzzp --zD {} -u FUZZ -H test:2 --oF {}".format(filename, filename_new)
    ).fuzz(save=filename_new):
        pass

    assert (
        len(
            list(
                wfuzz.get_session(
                    "-z wfuzzp --zD {} --slice r.headers.request.test=2 --dry-run -u FUZZ".format(
                        filename_new
                    )
                ).fuzz()
            )
        )
        == 1
    )
    assert (
        len(
            list(
                wfuzz.get_session(
                    "-z wfuzzp --zD {} --slice FUZZ[r.headers.request.test]=1 --dry-run -u FUZZ".format(
                        filename_new
                    )
                ).fuzz()
            )
        )
        == 1
    )
