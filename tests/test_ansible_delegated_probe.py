"""Guard delegated HTTPS checks against sshpass misclassifying failed commands."""
from pathlib import Path

import yaml


def test_delegated_agent_probe_preserves_actual_failure():
    source = Path(__file__).resolve().parents[1] / "ansible" / "site.yml"
    # site.yml includes import_playbook, so inspect raw YAML documents.
    plays = yaml.safe_load(source.read_text())
    verify = next(play for play in plays if play.get("name") == "Verify agents and authenticated management traffic")
    task = next(task for task in verify["tasks"] if task["name"] == "Verify agent HTTPS from the controller using its client identity")
    assert "ansible.builtin.shell" in task
    script = task["ansible.builtin.shell"]
    assert "probe_rc=$?" in script
    assert "exit 0" in script
    assert "OMNISSIAH_PROBE_RC=%s" in script
    assert task["register"] == "agent_https_probe"
    assert task["failed_when"] == "'OMNISSIAH_PROBE_RC=0' not in agent_https_probe.stdout_lines"
    assert task["delegate_to"] == "{{ groups.omnissiah[0] }}"
