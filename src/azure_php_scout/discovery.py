"""Bounded TCP connect discovery. Only open sockets are subsequently tested for HTTP(S)."""
import errno
import ipaddress
import selectors
import socket
import time

WEB_PORTS = [80, 81, 82, 83, 88, 443, 444, 591, 593, 800, 801, 808, 832, 981,
             1010, 1080, 1311, 2082, 2083, 2086, 2087, 2095, 2096, 2480,
             3000, 3001, 4000, 4200, 4443, 4567, 4848, 4993, 5000, 5001, 5104,
             5443, 5554, 5800, 5801, 5985, 5986, 6080, 6443, 7000, 7001, 7002,
             7080, 7081, 7443, 7474, 7473, 7777, 7800, 8000, 8001, 8002, 8008,
             8009, 8010, 8014, 8042, 8060, 8069, 8070, 8080, 8081, 8082, 8083,
             8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8095, 8100, 8118,
             8123, 8180, 8181, 8222, 8243, 8280, 8281, 8333, 8443, 8444, 8500,
             8530, 8531, 8800, 8834, 8880, 8888, 8899, 8983, 9000, 9001, 9043,
             9060, 9080, 9090, 9091, 9092, 9100, 9200, 9443, 9800, 9981, 9999,
             10000, 10443, 11235, 12443, 16080, 18080, 18081, 18091, 18092,
             20000, 28017, 30000, 32000, 50000, 50070]
TLS_PORTS = [443, 444, 2083, 2087, 2096, 4443, 4993, 5001, 5443, 5986, 6443,
             7002, 7081, 7443, 7473, 8042, 8084, 8243, 8333, 8443, 8444, 8531,
             8834, 9043, 9443, 10443, 12443, 18091]


def discover_open_ports(addresses, ports, *, workers=256, timeout=1, rate=1000,
                        stop, progress=None):
    """Yield (IP, port) once per successful TCP connection, with O(workers) sockets.

    A timeout is 'filtered/timeout', never asserted to mean closed. The port-first
    order spreads work across the fleet rather than finishing a whole host first.
    """
    addresses = list(dict.fromkeys(addresses))
    ports = list(dict.fromkeys(ports))
    # Discover likely web ports first even in a full-range scan.
    selected = set(ports)
    preferred = [port for port in WEB_PORTS if port in selected]
    order = preferred + sorted(set(ports).difference(preferred))
    jobs = iter((address, port) for port in order for address in addresses)
    families = {address: socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
                for address in addresses}
    stats = dict(total=len(addresses) * len(ports), attempted=0, checked=0, open=0,
                 closed=0, timedOut=0, errors=0, addresses=len(addresses), portsPerAddress=len(ports))
    pending, exhausted = {}, False
    next_attempt, next_progress = 0.0, 0.0
    transient = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR}
    local_errors = {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM, errno.EADDRNOTAVAIL}

    def finish(sock, outcome):
        address, port, _ = pending.pop(sock)
        selector.unregister(sock)
        sock.close()
        stats["checked"] += 1
        stats[outcome] += 1
        return address, port

    with selectors.DefaultSelector() as selector:
        try:
            while (pending or not exhausted) and not stop.is_set():
                now = time.monotonic()
                while not exhausted and len(pending) < workers and now >= next_attempt and not stop.is_set():
                    try:
                        address, port = next(jobs)
                    except StopIteration:
                        exhausted = True
                        break
                    sock = socket.socket(families[address], socket.SOCK_STREAM)
                    sock.setblocking(False)
                    try:
                        error = sock.connect_ex((address, port))
                    except OSError:
                        sock.close()
                        raise
                    stats["attempted"] += 1
                    next_attempt = max(next_attempt, now) + 1 / rate
                    if error in transient:
                        pending[sock] = (address, port, now + timeout)
                        selector.register(sock, selectors.EVENT_WRITE)
                    else:
                        sock.close()
                        if error in local_errors:
                            raise OSError(error, "Local socket capacity exhausted; reduce --port-workers or --port-rate")
                        stats["checked"] += 1
                        stats["open" if error == 0 else "closed" if error == errno.ECONNREFUSED else "errors"] += 1
                        if error == 0:
                            yield address, port
                    now = time.monotonic()
                wait = 0.05
                if not exhausted and len(pending) < workers:
                    wait = min(wait, max(0, next_attempt - time.monotonic()))
                if pending:
                    wait = min(wait, max(0, min(item[2] for item in pending.values()) - time.monotonic()))
                for key, _ in selector.select(wait):
                    sock = key.fileobj
                    error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if error in local_errors:
                        raise OSError(error, "Local socket capacity exhausted; reduce discovery concurrency")
                    outcome = "open" if error == 0 else "closed" if error == errno.ECONNREFUSED else "errors"
                    result = finish(sock, outcome)
                    if error == 0:
                        yield result
                now = time.monotonic()
                for sock, (_, _, deadline) in list(pending.items()):
                    if deadline <= now:
                        finish(sock, "timedOut")
                if progress and now >= next_progress:
                    progress(dict(stats))
                    next_progress = now + 1
        finally:
            for sock in list(pending):
                selector.unregister(sock)
                sock.close()
            if progress:
                progress(dict(stats))
