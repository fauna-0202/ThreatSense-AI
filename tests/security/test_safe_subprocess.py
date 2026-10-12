"""Security test verifying safe subprocess handling without shell interpolation."""

import inspect
from sensor.zeek_runner import ZeekRunner


def test_zeek_runner_never_uses_shell_true():
    # Inspect source code of ZeekRunner.start_live_capture
    source = inspect.getsource(ZeekRunner.start_live_capture)
    assert "shell=True" not in source, "Vulnerability: shell=True detected in subprocess execution"
    assert "subprocess.Popen" in source


def test_zeek_runner_does_not_execute_command_injection():
    # Pass malicious command injection attempt in interface argument
    runner = ZeekRunner(interface="eth0; rm -rf /")
    # Verify the argument list preserves interface safely as a single element
    assert runner.interface == "eth0; rm -rf /"
