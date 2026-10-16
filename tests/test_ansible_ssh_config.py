"""Regression check for sshpass handling of nonzero remote command exits."""
from configparser import ConfigParser
from pathlib import Path


def test_ansible_ssh_suppresses_informational_session_close_messages():
    config = ConfigParser()
    config.read(Path(__file__).resolve().parents[1] / "ansible" / "ansible.cfg")
    args = config["ssh_connection"]["ssh_args"].split()
    assert "-o" in args
    assert "LogLevel=ERROR" in args
    assert "ControlMaster=no" in args
    assert "ControlPersist=no" in args
