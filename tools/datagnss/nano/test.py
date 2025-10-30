#! /usr/bin/env python3
from .nano_cmd import DataGnssNano


def test_parse_hex_payload():
    payload = DataGnssNano._parse_hex_payload("F1 D9 06 09 08 00 # comment\n")
    assert payload == bytes.fromhex("F1 D9 06 09 08 00")


def test_parse_hex_payload_with_prefix():
    payload = DataGnssNano._parse_hex_payload("0xF1 0xD9 0x06 0x09")
    assert payload == bytes.fromhex("F1 D9 06 09")


def test_parse_hex_payload_empty_line():
    assert DataGnssNano._parse_hex_payload("# only comment") is None


def test_parse_hex_payload_without_spaces():
    payload = DataGnssNano._parse_hex_payload("F1D90609")
    assert payload == bytes.fromhex("F1 D9 06 09")


def test_decode_strings_mon_ver_example():
    payload = bytes.fromhex(
        "33 2E 30 31 38 2E 32 35 36 34 30 33 30 63 00 00 "
        "44 31 30 50 41 2E 36 34 39 32 35 62 65 66 37 00"
    )
    strings = DataGnssNano._decode_strings(payload, 16)
    assert strings[0] == "3.018.2564030c"
    assert strings[1].startswith("D10P")
