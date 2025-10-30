#! /usr/bin/env python3
import logging
import time
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .serial_comm import SerialComm

logging.basicConfig(format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)
log.setLevel("ERROR")


class DataGnssError(Exception):
    """Base exception for Datagnss helpers."""


class DataGnssTimeoutError(DataGnssError):
    """Raised when the receiver does not respond within the expected time."""


class DataGnssChecksumError(DataGnssError):
    """Raised when a message checksum validation fails."""


class DataGnssNano:
    """
    Helper to communicate with Datagnss Nano receivers over a serial link.

    The device uses an ALS framing similar to UBX: preamble 0xF1 0xD9, followed by
    group ID, sub ID, payload length (little endian), payload and two Fletcher checksum bytes.
    """

    PREAMBLE = b"\xF1\xD9"
    STORE_COMMAND = bytes.fromhex("F1 D9 06 09 08 00 00 00 00 00 07 00 00 00 1E 17")
    MON_VER_GROUP = 0x0A
    MON_VER_SUB = 0x04

    def __init__(
        self,
        address: str,
        baudrate: int = 230400,
        timeout: float = 2,
        cmd_delay: float = 0.1,
        debug: bool = False,
    ) -> None:
        self.comm = SerialComm(
            address=address,
            baudrate=baudrate,
            timeout=timeout,
            cmd_delay=cmd_delay,
        )
        if debug:
            log.setLevel("DEBUG")
        self.debug = debug
        self._mon_ver_cache: Optional[Tuple[str, str]] = None
        self.connect()

    def connect(self) -> None:
        """Clear any buffered data before starting a new session."""
        log.debug("Connecting to Datagnss Nano receiver")
        self.comm.device_serial.reset_input_buffer()

    def close(self) -> None:
        log.debug("Closing connection")
        self.comm.close()

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.close()

    # --------------------------------- Query helpers --------------------------------- #

    def get_receiver_model(self) -> str:
        """Return the hardware identifier (e.g. D10P...)."""
        _, hardware = self._read_mon_ver()
        return hardware or "Datagnss_Nano"

    def get_receiver_firmware(self) -> str:
        """Return the firmware revision string."""
        software, hardware = self._read_mon_ver()
        return f"{software} ({hardware})" if hardware else software

    def set_factory_default(self) -> None:
        raise NotImplementedError("Factory reset is not defined for Datagnss Nano yet")

    def send_config_file(self, file: str, perm: bool = False) -> None:
        """
        Send configuration commands from a text file.

        Expected format: one hex payload per line, comments starting with '#'.
        """
        path = Path(file)
        if not path.exists():
            raise FileNotFoundError(file)

        with path.open("r", encoding="utf-8") as stream:
            for index, line in enumerate(stream, start=1):
                payload = self._parse_hex_payload(line)
                if payload is None:
                    continue
                log.debug("Sending cfg line %s: %s", index, payload.hex(" ").upper())
                self._write_raw(payload)
                # give the device time to process without assuming a specific ACK format
                time.sleep(self.comm.cmd_delay)

        if perm:
            self.set_config_permanent()

    def set_config_permanent(self) -> None:
        """Persist the current configuration to non-volatile memory."""
        log.debug("Saving configuration to non-volatile memory")
        self._write_raw(self.STORE_COMMAND)
        print("Settings saved")

    # --------------------------------- Internal helpers --------------------------------- #

    def _read_mon_ver(self, refresh: bool = False) -> Tuple[str, str]:
        if self._mon_ver_cache is not None and not refresh:
            return self._mon_ver_cache

        payload = self._request(self.MON_VER_GROUP, self.MON_VER_SUB, timeout=1.0)
        strings = self._decode_strings(payload, chunk=16)
        software = strings[0] if strings else ""
        hardware = strings[1] if len(strings) > 1 else ""
        self._mon_ver_cache = (software, hardware)
        return self._mon_ver_cache

    def _request(self, group: int, sub: int, payload: bytes = b"", timeout: float = 1.0) -> bytes:
        message = self._build_message(group, sub, payload)
        self.comm.device_serial.reset_input_buffer()
        self._write_raw(message)
        _, _, response_payload = self._read_message(expected=(group, sub), timeout=timeout)
        return response_payload

    def _write_raw(self, payload: bytes) -> None:
        self.comm.device_serial.reset_output_buffer()
        self.comm.send_raw(payload)

    def _read_message(
        self,
        expected: Optional[Tuple[int, int]] = None,
        timeout: float = 1.0,
    ) -> Tuple[int, int, bytes]:
        end_time = time.monotonic() + timeout
        ser = self.comm.device_serial

        while time.monotonic() < end_time:
            first = ser.read(1)
            if not first:
                continue
            if first != self.PREAMBLE[:1]:
                continue
            second = ser.read(1)
            if second != self.PREAMBLE[1:2]:
                continue

            header = ser.read(4)
            if len(header) < 4:
                continue
            group, sub = header[0], header[1]
            length = int.from_bytes(header[2:4], "little")

            payload = ser.read(length)
            if len(payload) < length:
                continue

            checksum = ser.read(2)
            if len(checksum) < 2:
                continue

            ck1, ck2 = self._calculate_checksum(bytes([group, sub]) + header[2:4] + payload)
            if checksum != bytes([ck1, ck2]):
                log.debug(
                    "Checksum mismatch: expected %s got %s",
                    checksum.hex(),
                    bytes([ck1, ck2]).hex(),
                )
                raise DataGnssChecksumError("Checksum mismatch")

            if expected and (group, sub) != expected:
                log.debug("Unexpected message: %s %s (expecting %s)", group, sub, expected)
                continue

            return group, sub, payload

        raise DataGnssTimeoutError("Timed out waiting for Datagnss response")

    @staticmethod
    def _build_message(group: int, sub: int, payload: bytes) -> bytes:
        length = len(payload).to_bytes(2, "little")
        content = bytes([group, sub]) + length + payload
        ck1, ck2 = DataGnssNano._calculate_checksum(content)
        return DataGnssNano.PREAMBLE + content + bytes([ck1, ck2])

    @staticmethod
    def _calculate_checksum(data: bytes) -> Tuple[int, int]:
        ck1 = 0
        ck2 = 0
        for byte in data:
            ck1 = (ck1 + byte) & 0xFF
            ck2 = (ck2 + ck1) & 0xFF
        return ck1, ck2

    @staticmethod
    def _decode_strings(payload: bytes, chunk: int) -> List[str]:
        strings: List[str] = []
        for start in range(0, len(payload), chunk):
            segment = payload[start : start + chunk]
            if not segment:
                continue
            text = segment.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()
            if text:
                strings.append(text)
        return strings

    @staticmethod
    def _parse_hex_payload(line: str) -> Optional[bytes]:
        clean = line.split("#", 1)[0].strip()
        if not clean:
            return None
        for sep in (",", ";"):
            clean = clean.replace(sep, " ")
        tokens = clean.split()
        payload = bytearray()
        try:
            for token in tokens:
                token = token.strip()
                if not token:
                    continue
                if token.lower().startswith("0x"):
                    token = token[2:]
                if len(token) % 2 != 0:
                    raise ValueError(f"Odd number of hex digits: {token}")
                for i in range(0, len(token), 2):
                    payload.append(int(token[i : i + 2], 16))
        except ValueError as exc:
            raise ValueError(f"Invalid hex payload: {line.strip()}") from exc
        return bytes(payload)
