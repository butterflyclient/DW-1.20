"""Bounded access retries for fixture files held by a Windows durable writer."""

import errno
import os
import time


def retry_sharing(operation):
    deadline = time.monotonic() + 1
    while True:
        try:
            return operation()
        except PermissionError as error:
            code = getattr(error, "winerror", None)
            # CRT file opens can report EACCES without the native Windows code.
            sharing = code in (32, 33) or (
                os.name == "nt" and code is None and error.errno == errno.EACCES
            )
            if not sharing or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)
