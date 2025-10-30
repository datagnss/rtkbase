#! /usr/bin/env python3

import argparse
import logging
import sys
import time
from enum import Enum
from operator import methodcaller

from datagnss.nano.nano_cmd import DataGnssNano

logging.basicConfig(format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)
log.setLevel("ERROR")


class CmdMapping(Enum):
    """Mapping human-friendly commands to DataGnssNano methods."""

    get_model = "get_receiver_model"
    get_firmware = "get_receiver_firmware"
    send_config_file = "send_config_file"


def arg_parse():
    parser = argparse.ArgumentParser(
        prog="Datagnss tool",
        description="Utility to interact with Datagnss Nano GNSS receivers",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-p", "--port", help="Serial port to connect to", type=str)
    parser.add_argument("-b", "--baudrate", help="Serial baudrate", default=230400, type=int)
    parser.add_argument(
        "-c",
        "--command",
        nargs="+",
        help=(
            "Command to execute.\n"
            "Available commands: 'get_model' 'get_firmware' 'send_config_file <path>'"
        ),
        type=str,
    )
    parser.add_argument(
        "-s",
        "--store",
        action="store_true",
        help="Persist settings after send_config_file",
        default=False,
    )
    parser.add_argument(
        "-r",
        "--retry",
        help="Number of retries on failure",
        default=0,
        type=int,
    )
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")
    return parser.parse_args()


if __name__ == "__main__":
    args = arg_parse()
    if args.debug:
        log.setLevel("DEBUG")
        log.debug("Arguments: %s", args)
    if not args.command:
        print("Missing --command option")
        sys.exit(1)
    command = args.command[0]
    if command not in CmdMapping.__members__:
        print(f"Unsupported command: {command}")
        sys.exit(1)
    retries = 0
    retry_delay = 2
    success = False
    while retries <= args.retry:
        try:
            with DataGnssNano(
                args.port, baudrate=args.baudrate, timeout=2, cmd_delay=0.1, debug=args.debug
            ) as gnss:
                res = methodcaller(CmdMapping[command].value, *args.command[1:])(gnss)
                if isinstance(res, str):
                    print(res)
                if args.store and command == "send_config_file":
                    gnss.set_config_permanent()
            success = True
            break
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log.debug("Exception while running command", exc_info=exc)
            retries += 1
            if retries <= args.retry:
                log.warning("Failed...retrying in %ss", retry_delay)
                time.sleep(retry_delay)
    if not success:
        print("Command failed!", file=sys.stderr)
        sys.exit(1)
