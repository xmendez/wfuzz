import pytest
import wfuzz


@pytest.mark.parametrize(
    "params, expected_result",
    [
        (
            {
                "iterator": "zip",
                "payloads": [
                    ("range", {"default": "0-2", "encoder": None}, None),
                    ("range", {"default": "0-2", "encoder": None}, None),
                ],
            },
            [("0", "0"), ("1", "1"), ("2", "2")],
        ),
        (
            {
                "iterator": "chain",
                "payloads": [
                    ("range", {"default": "0-2", "encoder": None}, None),
                    ("range", {"default": "0-2", "encoder": None}, None),
                ],
            },
            [("0",), ("0",), ("1",), ("1",), ("2",), ("2",)],
        ),
        (
            {
                "iterator": "product",
                "payloads": [
                    ("range", {"default": "0-2", "encoder": None}, None),
                    ("range", {"default": "0-2", "encoder": None}, None),
                ],
            },
            [
                ("0", "0"),
                ("0", "1"),
                ("0", "2"),
                ("1", "0"),
                ("1", "1"),
                ("1", "2"),
                ("2", "0"),
                ("2", "1"),
                ("2", "2"),
            ],
        ),
        (
            {"payloads": [("range", {"default": "0-4", "encoder": None}, None)]},
            [("0",), ("1",), ("2",), ("3",), ("4",)],
        ),
        (
            {
                "payloads": [
                    ("buffer_overflow", {"default": "10", "encoder": None}, None)
                ]
            },
            [("AAAAAAAAAA",)],
        ),
        (
            {"payloads": [("hexrange", {"default": "09-10", "encoder": None}, None)]},
            [("09",), ("0a",), ("0b",), ("0c",), ("0d",), ("0e",), ("0f",), ("10",)],
        ),
        (
            {"payloads": [("hexrange", {"default": "009-00B", "encoder": None}, None)]},
            [("009",), ("00a",), ("00b",)],
        ),
        (
            {
                "payloads": [
                    ("ipnet", {"default": "192.168.0.1/30", "encoder": None}, None)
                ]
            },
            [("192.168.0.1",), ("192.168.0.2",)],
        ),
        (
            {
                "payloads": [
                    (
                        "iprange",
                        {"default": "192.168.0.1-192.168.0.2", "encoder": None},
                        None,
                    )
                ]
            },
            [("192.168.0.1",), ("192.168.0.2",)],
        ),
        (
            {"payloads": [("list", {"default": "a-b", "encoder": None}, None)]},
            [("a",), ("b",)],
        ),
        (
            {"payloads": [("list", {"default": "a\\-b-b", "encoder": None}, None)]},
            [("a-b",), ("b",)],
        ),
        (
            {"payloads": [("range", {"default": "1-2", "encoder": None}, None)]},
            [("1",), ("2",)],
        ),
    ],
)
def test_payload_iterator(params, expected_result):
    assert sorted(list(wfuzz.payload(**params))) == sorted(expected_result)


@pytest.mark.parametrize(
    "payload, expected_result",
    [(range(4), [0, 1, 2, 3]), ([list(range(2)), list(range(2))], [[0, 1], [0, 1]])],
)
def test_get_payload(payload, expected_result):
    assert sorted(wfuzz.get_payload(payload).data.get("dictio")[0]) == sorted(
        expected_result
    )
