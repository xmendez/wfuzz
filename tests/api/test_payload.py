import pytest
import wfuzz


@pytest.mark.parametrize(
    "params, expected_result",
    [
        (
            {
                'iterator': 'zip',
                'payloads': [
                    (
                        'range',
                        {
                            'default': '0-2',
                            'encoder': None
                        },
                        None
                    ),
                    (
                        'range',
                        {
                            'default': '0-2',
                            'encoder': None
                        },
                        None
                    )
                ]
            },
            [('0', '0'), ('1', '1'), ('2', '2')]
        ),
        (
            {
                'iterator': 'chain',
                'payloads': [
                    (
                        'range',
                        {
                            'default': '0-2',
                            'encoder': None
                        },
                        None
                    ),
                    (
                        'range',
                        {
                            'default': '0-2',
                            'encoder': None
                        },
                        None
                    )
                ]
            },
            [('0',), ('0',), ('1',), ('1',), ('2',), ('2',)]
        ),
        (
            {
                'iterator': 'product',
                'payloads': [
                    (
                        'range',
                        {
                            'default': '0-2',
                            'encoder': None
                        },
                        None
                    ),
                    (
                        'range',
                        {
                            'default': '0-2',
                            'encoder': None
                        },
                        None
                    )
                ]
            },
            [('0', '0'), ('0', '1'), ('0', '2'), ('1', '0'), ('1', '1'), ('1', '2'), ('2', '0'), ('2', '1'), ('2', '2')]
        ),
    ]
)
def test_payload(params, expected_result):
    assert sorted(list(wfuzz.payload(**params))) == sorted(expected_result)
