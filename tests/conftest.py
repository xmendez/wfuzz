import pytest

from wfuzz.fuzzrequest import FuzzRequest


@pytest.fixture
def full_fuzzreq(request):
    raw_req, raw_resp = request.param
    fr = FuzzRequest()
    fr.update_from_raw_http(raw_req, 'http', raw_resp, None)

    return fr


@pytest.fixture
def fuzzreq_from_url(request):
    fr = FuzzRequest()
    fr.url = request.param

    return fr
