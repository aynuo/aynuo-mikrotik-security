"""Desktop launcher for the AYNUO web dashboard executable."""
from __future__ import annotations

import socket
import threading
import time
import webbrowser
import logging
import os
import sys
from pathlib import Path

import uvicorn


def _port() -> int:
    for port in range(8765, 8776):
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("Ports 8765 through 8775 are occupied. Close another service and retry.")


def main() -> None:
    data_dir = Path(os.getenv("LOCALAPPDATA", Path.home())) / "AYNUO" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    log_file = (data_dir / "launcher.log").open("a", encoding="utf-8", buffering=1)
    sys.stdout = log_file
    sys.stderr = log_file
    logging.basicConfig(stream=log_file, level=logging.INFO, force=True)
    logging.info("AYNUO launcher starting")
    port = _port()
    from app.main import app

    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=port,
        log_config=None, access_log=False,
    ))
    thread = threading.Thread(target=server.run, name="aynuo-web", daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    for _ in range(80):
        if server.started:
            logging.info("Dashboard ready at %s", url)
            webbrowser.open(url)
            break
        if not thread.is_alive():
            logging.exception("AYNUO server thread stopped during startup")
            raise RuntimeError(f"AYNUO could not start. See {data_dir / 'launcher.log'}")
        time.sleep(0.25)
    else:
        server.should_exit = True
        logging.error("AYNUO server startup timed out")
        raise RuntimeError(f"AYNUO did not become ready. See {data_dir / 'launcher.log'}")
    try:
        while thread.is_alive():
            thread.join(1)
    except KeyboardInterrupt:
        server.should_exit = True
        thread.join(5)


if __name__ == "__main__":
    main()

