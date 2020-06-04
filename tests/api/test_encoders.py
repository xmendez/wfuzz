import pytest
import wfuzz


@pytest.mark.parametrize(
    "encoder, text, expected_result",
    [
        ("none", "test", "test"),
        ("urlencode", "../=?&", "../%3D%3F%26"),
        ("double_urlencode", "../=?&", "../%253D%253F%2526"),
        ("double_urlencode", "../=?&", "../%253D%253F%2526"),
        ("base64", "admin", "YWRtaW4="),
        ("sha1", "admin", "d033e22ae348aeb5660fc2140aec35850c4da997"),
        ("md5", "admin", "21232f297a57a5a743894a0e4a801fc3"),
        ("hexlify", "admin", "61646d696e"),
        ("html_escape", "<>&'\"/", "&lt;&gt;&amp;&#x27;&quot;/"),
        ("html_decimal", "<>&'\"/", "&#60;&#62;&#38;&#39;&#34;&#47;"),
        ("html_hexadecimal", "<>&'\"/", "&#x3c;&#x3e;&#x26;&#x27;&#x22;&#x2f;"),
        ("mysql_char", "admin", "CHAR(97,100,109,105,110)"),
        ("mssql_char", "admin", "CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)"),
        ("oracle_char", "admin", "chr(97)||chr(100)||chr(109)||chr(105)||chr(110)"),
    ],
)
def test_encode(encoder, text, expected_result):
    assert wfuzz.encode(encoder, text) == expected_result


@pytest.mark.parametrize(
    "encoder, text, expected_result",
    [
        ("none", "test", "test"),
        ("urlencode", "../=?&", "../%3D%3F%26"),
        ("double_urlencode", "../=?&", "../%253D%253F%2526"),
        ("double_urlencode", "../=?&", "../%253D%253F%2526"),
        ("base64", "admin", "YWRtaW4="),
        ("hexlify", "admin", "61646d696e"),
        ("mysql_char", "admin", "CHAR(97,100,109,105,110)"),
        ("mssql_char", "admin", "CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)"),
        ("oracle_char", "admin", "chr(97)||chr(100)||chr(109)||chr(105)||chr(110)"),
    ],
)
def test_decode(encoder, text, expected_result):
    assert wfuzz.decode(encoder, expected_result) == text
