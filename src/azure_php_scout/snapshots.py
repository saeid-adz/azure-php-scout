"""Atomic report updates, including temporary Windows reader locks."""
import time


def replace_snapshot(temporary, destination):
    """Keep the old snapshot intact while briefly retrying Windows sharing conflicts."""
    for attempt in range(21):
        try:
            return temporary.replace(destination)
        except PermissionError as exc:
            if getattr(exc, "winerror", None) not in (5, 32, 33) or attempt == 20:
                raise
            time.sleep(0.05)
