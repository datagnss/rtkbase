#! /usr/bin/env python3
import serial
import time
from typing import List


class SerialComm:
    """Light wrapper around pyserial for Datagnss receivers."""

    def __init__(
        self,
        address: str,
        baudrate: int = 230400,
        timeout: float = 5,
        write_timeout: float = 5,
        cmd_delay: float = 0.1,
        on_error=None,
        byte_encoding: str = "ISO-8859-1",
        line_ending: str = "\r\n",
    ) -> None:
        self.cmd_delay = cmd_delay
        self.on_error = on_error
        self.byte_encoding = byte_encoding
        self.line_ending = line_ending.encode(self.byte_encoding)
        self.device_serial = serial.Serial(
            port=address,
            baudrate=baudrate,
            timeout=timeout,
            write_timeout=write_timeout,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            xonxoff=False,
            rtscts=False,
            dsrdtr=False,
        )

    def send(self, cmd: str) -> None:
        payload = cmd.encode(self.byte_encoding)
        if self.line_ending:
            payload += self.line_ending
        self.device_serial.write(payload)
        time.sleep(self.cmd_delay)

    def send_raw(self, cmd: bytes) -> None:
        self.device_serial.write(cmd)
        time.sleep(self.cmd_delay)

    def read_lines(self) -> List[str]:
        read = self.device_serial.readlines()
        return [
            line.decode(self.byte_encoding, errors="ignore").strip()
            for line in read
            if line.strip()
        ]

    def read_until(self, expected: str = "\r\n") -> List[str]:
        read = self.device_serial.read_until(expected=expected.encode())
        decoded = read.decode(self.byte_encoding, errors="ignore").splitlines()
        return [line for line in decoded if line]

    def read_until_line(self, expected: str = "\r\n") -> str:
        read_start = self.device_serial.read_until(expected=expected.encode())
        read_start = (
            read_start.decode(self.byte_encoding, errors="ignore").strip().splitlines()[-1]
        )
        if expected in read_start:
            read_end = self.device_serial.readline().decode(
                self.byte_encoding, errors="ignore"
            )
            return read_start + read_end
        return read_start

    def read_raw(self, size: int) -> bytes:
        return self.device_serial.read(size)

    def read_available(self) -> List[str]:
        """Read and decode the currently buffered bytes without blocking."""
        waiting = self.device_serial.in_waiting
        if not waiting:
            return []
        raw = self.device_serial.read(waiting)
        decoded = raw.decode(self.byte_encoding, errors="ignore")
        return [line.strip() for line in decoded.splitlines() if line.strip()]

    def close(self) -> None:
        self.device_serial.close()
