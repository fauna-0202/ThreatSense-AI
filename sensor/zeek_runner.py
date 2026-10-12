"""Zeek process manager and live/replay sensor runner."""

import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, List
from threatsense.config import settings
from threatsense.logging import logger
from sensor.health import sensor_tracker, SensorState


class ZeekRunner:
    """Manages Zeek network monitoring process and logs directory."""

    def __init__(
        self,
        interface: Optional[str] = None,
        zeek_bin: Optional[str] = None,
        log_dir: Optional[str] = None,
    ):
        self.interface = interface or settings.sensor.authorized_interface
        self.zeek_bin = zeek_bin or settings.sensor.zeek_bin
        self.log_dir = Path(log_dir or settings.sensor.log_dir)
        self.process: Optional[subprocess.Popen] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def check_zeek_availability(self) -> bool:
        """Verifies if Zeek executable is installed on the system PATH or configured path."""
        path = shutil.which(self.zeek_bin)
        return path is not None

    def start_live_capture(self) -> bool:
        """Starts Zeek live network monitoring on configured authorized interface."""
        sensor_tracker.set_state(SensorState.STARTING)

        if not self.check_zeek_availability():
            err_msg = (
                f"Zeek binary '{self.zeek_bin}' not found on PATH. "
                "For Windows, install Zeek in WSL2 Ubuntu ('sudo apt install zeek') "
                "or switch to Replay Mode."
            )
            logger.warning(err_msg)
            sensor_tracker.set_state(SensorState.ERROR, error=err_msg)
            return False

        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Zeek command using safe argument list (token array, no shell execution)
        # -i <interface>: monitor interface
        # -C: ignore invalid checksums
        # LogAscii::use_json=T: output JSON logs
        cmd = [
            self.zeek_bin,
            "-i",
            self.interface,
            "-C",
            f"Log::default_logdir={self.log_dir.resolve()}",
            "LogAscii::use_json=T",
        ]

        logger.info(f"Starting Zeek sensor: {' '.join(cmd)}")
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.log_dir),
            )
            time.sleep(1.0)
            if self.process.poll() is not None:
                _, stderr = self.process.communicate()
                err_text = stderr.decode("utf-8", errors="replace")
                if "permission denied" in err_text.lower() or "operation not permitted" in err_text.lower():
                    state = SensorState.PERMISSION_REQUIRED
                else:
                    state = SensorState.ERROR
                sensor_tracker.set_state(state, error=err_text.strip())
                return False

            sensor_tracker.set_state(SensorState.CONNECTED)
            sensor_tracker.metadata["pid"] = self.process.pid
            sensor_tracker.metadata["interface"] = self.interface

            # Monitor process life
            self._stop_event.clear()
            self._monitor_thread = threading.Thread(target=self._supervise_process, daemon=True)
            self._monitor_thread.start()
            return True

        except PermissionError as pe:
            sensor_tracker.set_state(SensorState.PERMISSION_REQUIRED, error=str(pe))
            return False
        except Exception as e:
            sensor_tracker.set_state(SensorState.ERROR, error=str(e))
            return False

    def _supervise_process(self):
        while not self._stop_event.is_set():
            if self.process and self.process.poll() is not None:
                _, stderr = self.process.communicate()
                err = stderr.decode("utf-8", errors="replace").strip()
                logger.warning(f"Zeek sensor exited with code {self.process.returncode}: {err}")
                sensor_tracker.set_state(SensorState.ERROR, error=err or f"Exit code {self.process.returncode}")
                break
            time.sleep(2.0)

    def stop(self):
        self._stop_event.set()
        if self.process:
            logger.info("Stopping Zeek sensor process...")
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
            self.process = None
        sensor_tracker.set_state(SensorState.STOPPED)
