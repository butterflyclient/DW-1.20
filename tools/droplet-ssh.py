"""Key-only SSH operations against the pinned primary Replay DW droplet."""
import argparse
import pathlib
import sys
from remote_backend import connect


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['exec', 'put', 'get'])
    parser.add_argument('source')
    parser.add_argument('destination', nargs='?')
    args = parser.parse_args()
    with connect() as client:
        if args.operation == 'exec':
            _, out, error = client.exec_command(args.source)
            # Stream output so a build can be resumed through the normal PTY.
            while True:
                block = out.read(4096)
                if not block:
                    break
                sys.stdout.buffer.write(block)
                sys.stdout.buffer.flush()
            sys.stderr.buffer.write(error.read())
            return out.channel.recv_exit_status()
        with client.open_sftp() as sftp:
            if args.operation == 'put':
                sftp.put(args.source, args.destination)
            else:
                sftp.get(args.source, args.destination)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
