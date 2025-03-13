from unittest.mock import patch

import pytest

from memray.commands import main
from memray.commands.attach import AttachCommand, DetachCommand, recvall
from memray._errors import MemrayCommandError
from memray.commands.live import LiveCommand


@patch("memray.commands.attach.debugger_available")
class TestAttachSubCommand:
    def test_memray_attach_aggregated_without_output_file(
        self, is_debugger_available_mock, capsys
    ):
        # GIVEN
        is_debugger_available_mock.return_value = True

        # WHEN
        with pytest.raises(SystemExit):
            main(["attach", "--aggregate", "1234"])

        captured = capsys.readouterr()
        print("Error", captured.err)
        assert "Can't use aggregated mode without an output file." in captured.err

    class FakeSocket:
        """A simple fake socket for testing."""
        def __init__(self, recv_data: bytes = b""):
            self.recv_data = recv_data
            self.sent_data = b""

        def sendall(self, data: bytes) -> None:
            self.sent_data += data

        def shutdown(self, mode: int) -> None:
            pass

        def recv(self, bufsize: int) -> bytes:
            if self.recv_data:
                ret = self.recv_data
                self.recv_data = b""
                return ret
            return b""

    def test_attach_with_output_success(self, is_debugger_available_mock, tmp_path):
        """Test attach command with an output file (non-live mode) succeeds."""
        # Setup args with a valid output file and no duration
        from argparse import Namespace, ArgumentParser
        args = Namespace(
            verbose=False,
            duration=None,
            method="gdb",
            pid=1234,
            output=str(tmp_path / "output.txt"),
            force=True,
            aggregate=False,
            native=False,
            follow_fork=False,
            trace_python_allocators=False,
            no_compress=False,
        )
        parser = ArgumentParser()

        # Patch the inject_control_channel to return a fake socket with empty recv data (no error)
        attach_command = AttachCommand()
        fake_client = self.FakeSocket(recv_data=b"")
        attach_command.inject_control_channel = lambda method, pid, verbose=False: fake_client

        # Run the attach command; this should not raise an exception.
        attach_command.run(args, parser)

        # Verify the payload data sent contains the 'ACTIVATE' mode
        payload = fake_client.sent_data.decode("utf-8")
        assert "'ACTIVATE'" in payload, "Payload should contain activate command"

    def test_attach_with_duration_success(self, is_debugger_available_mock, tmp_path):
        """Test attach command with a tracking duration is using FOR_DURATION mode."""
        from argparse import Namespace, ArgumentParser
        args = Namespace(
            verbose=False,
            duration=5,
            method="gdb",
            pid=1234,
            output=str(tmp_path / "output.txt"),
            force=True,
            aggregate=False,
            native=False,
            follow_fork=False,
            trace_python_allocators=False,
            no_compress=False,
        )
        parser = ArgumentParser()

        attach_command = AttachCommand()
        fake_client = self.FakeSocket(recv_data=b"")
        attach_command.inject_control_channel = lambda method, pid, verbose=False: fake_client

        attach_command.run(args, parser)
        payload = fake_client.sent_data.decode("utf-8")
        assert "'FOR_DURATION'" in payload, "Payload should contain FOR_DURATION mode"
        assert "5" in payload, "Payload should contain the duration value"

    def test_attach_live_mode_success(self, is_debugger_available_mock, monkeypatch):
        """Test attach live mode branch (no output file) and ensure live interface is triggered."""
        from argparse import Namespace, ArgumentParser
        args = Namespace(
            verbose=False,
            duration=None,
            method="gdb",
            pid=1234,
            output=None,
            force=False,
            aggregate=False,
            native=False,
            follow_fork=False,
            trace_python_allocators=False,
            no_compress=False,
        )
        parser = ArgumentParser()

        attach_command = AttachCommand()
        fake_client = self.FakeSocket(recv_data=b"")
        attach_command.inject_control_channel = lambda method, pid, verbose=False: fake_client

        # Patch LiveCommand.start_live_interface to record the live port it is given
        live_called = []
        def fake_start_live_interface(self, live_port):
            live_called.append(live_port)
        monkeypatch.setattr(LiveCommand, "start_live_interface", fake_start_live_interface)

        # Run the attach command in live mode.
        attach_command.run(args, parser)
        # Ensure that the live interface was started with a valid port (non-zero)
        assert live_called, "Live interface should have been started"
        assert isinstance(live_called[0], int) and live_called[0] > 0, "Expected a valid live port"

    def test_detach_success(self, is_debugger_available_mock):
        """Test that detach command successfully sends DEACTIVATE."""
        from argparse import Namespace, ArgumentParser
        args = Namespace(
            verbose=False,
            method="gdb",
            pid=1234,
        )
        parser = ArgumentParser()

        detach_command = DetachCommand()
        fake_client = self.FakeSocket(recv_data=b"")
        detach_command.inject_control_channel = lambda method, pid, verbose=False: fake_client

        detach_command.run(args, parser)
        payload = fake_client.sent_data.decode("utf-8")
        assert "'DEACTIVATE'" in payload, "Payload should indicate detach mode"

    def test_detach_error(self, is_debugger_available_mock):
        """Test that detach command raises an error if a non-empty error message is received."""
        from argparse import Namespace, ArgumentParser
        args = Namespace(
            verbose=False,
            method="gdb",
            pid=1234,
        )
        parser = ArgumentParser()

        detach_command = DetachCommand()
        # Simulate that the fake socket returns a non-empty error message.
        fake_client = self.FakeSocket(recv_data=b"Some error occurred")
        detach_command.inject_control_channel = lambda method, pid, verbose=False: fake_client

        with pytest.raises(MemrayCommandError) as excinfo:
            detach_command.run(args, parser)
        assert "Failed to stop tracking" in str(excinfo.value), "Expected detach error message"