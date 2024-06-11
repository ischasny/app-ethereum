import pytest

from ragger.error import ExceptionRAPDU
from ragger.backend import BackendInterface

from client.client import EthAppClient, StatusWord


def test_provide_erc20_token(backend: BackendInterface):

    app_client = EthAppClient(backend)

    # pylint: disable=line-too-long
    cert_apdu = "010101020102100401020000110400000002120100130200021401011604000000002009436f696e5f6d657461300200063101083201213321024cca8fad496aa5040a00a7eb2f5cc3b85376d88ba147a7d7054a99c64056188734010135010315483046022100dbd6bcd92ee98742edd0c43e66af6d6b7928572aa416713c2b1d63a1f37b035e022100ae23e9b3af524a8b92b61fff814a8313caf2de3a9d1561fd1efc91cbc5725b25"
    # pylint: enable=line-too-long
    response = app_client.send_raw(0xb0, 0x06, 0x08, 0x00, bytes.fromhex(cert_apdu))
    assert response.status == StatusWord.OK

    addr = bytes.fromhex("e41d2489571d322189246dafa5ebde1f4699f498")
    response = app_client.provide_token_metadata("ZRX", addr, 18, 1)
    assert response.status == StatusWord.OK


def test_provide_erc20_token_error(backend: BackendInterface):

    app_client = EthAppClient(backend)

    addr = bytes.fromhex("e41d2489571d322189246dafa5ebde1f4699f498")
    sign = bytes.fromhex("deadbeef")
    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_token_metadata("ZRX", addr, 18, 1, sign)

    assert e.value.status == StatusWord.INVALID_DATA
