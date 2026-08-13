import subprocess
from types import SimpleNamespace

import process_watcher


def make_proc(**overrides):
    proc = {
        "pid": "100",
        "ppid": "1",
        "cpu": "0.0",
        "mem": "0.1",
        "comm": "/usr/bin/python3",
        "args": "python3 safe_worker.py",
    }
    proc.update(overrides)
    return proc


def test_flag_reasons_returns_empty_for_clean_process():
    assert process_watcher.flag_reasons(make_proc(), cpu_threshold=70.0) == []


def test_flag_reasons_identifies_keywords_paths_and_cpu_threshold():
    proc = make_proc(cpu="72.5", comm="/tmp/xmrig", args="/tmp/xmrig --donate-level 0")

    reasons = process_watcher.flag_reasons(proc, cpu_threshold=70.0)

    assert "keyword:xmrig" in reasons
    assert "path:/tmp/" in reasons
    assert "high_cpu:72.5%" in reasons


def test_flag_reasons_matches_multitoken_command_keyword_case_insensitively():
    proc = make_proc(args="PowerShell -Enc SQBFAFgA")

    assert process_watcher.flag_reasons(proc, cpu_threshold=70.0) == [
        "keyword:powershell -enc"
    ]


def test_flag_reasons_uses_cpu_threshold_inclusively():
    proc = make_proc(cpu="20.0")

    assert process_watcher.flag_reasons(proc, cpu_threshold=20.0) == ["high_cpu:20.0%"]
    assert process_watcher.flag_reasons(proc, cpu_threshold=20.1) == []


def test_flag_reasons_ignores_non_numeric_cpu_values():
    proc = make_proc(cpu="not-a-number", args="/usr/bin/python3 safe_worker.py")

    assert process_watcher.flag_reasons(proc, cpu_threshold=1.0) == []


def test_run_ps_parses_process_rows_and_skips_malformed_lines(monkeypatch):
    ps_output = """
      101     1  0.0  0.1 /usr/bin/python3 python3 app.py --safe mode

      202     1 15.5  1.2 /tmp/xmrig /tmp/xmrig --threads 2
      303     1  0.0
    """

    def fake_run(cmd, capture_output, text, check):
        assert cmd == ["ps", "-axo", "pid=,ppid=,%cpu=,%mem=,comm=,args="]
        assert capture_output is True
        assert text is True
        assert check is True
        return SimpleNamespace(stdout=ps_output)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert process_watcher.run_ps() == [
        {
            "pid": "101",
            "ppid": "1",
            "cpu": "0.0",
            "mem": "0.1",
            "comm": "/usr/bin/python3",
            "args": "python3 app.py --safe mode",
        },
        {
            "pid": "202",
            "ppid": "1",
            "cpu": "15.5",
            "mem": "1.2",
            "comm": "/tmp/xmrig",
            "args": "/tmp/xmrig --threads 2",
        },
    ]


def test_scan_sorts_findings_by_cpu_and_applies_max_items(monkeypatch):
    monkeypatch.setattr(
        process_watcher,
        "run_ps",
        lambda: [
            make_proc(pid="101", cpu="10.0", args="/tmp/suspicious-helper"),
            make_proc(pid="202", cpu="95.5", args="python3 safe_worker.py"),
            make_proc(pid="303", cpu="35.0", args="nc -e /bin/sh"),
        ],
    )

    findings = process_watcher.scan(cpu_threshold=50.0, max_items=2)

    assert [row["pid"] for row in findings] == ["202", "303"]
    assert findings[0]["reasons"] == "high_cpu:95.5%"
    assert "keyword:nc -e" in findings[1]["reasons"]


def test_print_findings_reports_no_findings(capsys):
    process_watcher.print_findings([])

    output = capsys.readouterr().out
    assert "Flagged processes: 0" in output
    assert "No suspicious flags found with current rules." in output
