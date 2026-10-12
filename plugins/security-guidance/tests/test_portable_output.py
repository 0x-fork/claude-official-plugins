import json

import pytest

from conftest import (
    STUB_VULN, VULN_PY, edit_payload, metrics_of, run_hook, stop_payload, ups_payload,
)

# What a host with a closed hook output schema accepts.
STOP_FIELDS = {"continue", "decision", "reason", "stopReason", "suppressOutput", "systemMessage"}
POST_TOOL_USE_FIELDS = STOP_FIELDS | {"hookSpecificOutput"}
HOST_MARKERS = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "PLUGIN_ROOT",
                "SECURITY_GUIDANCE_PORTABLE_OUTPUT")


def _env(hook_env, **extra):
    env = {k: v for k, v in hook_env.items() if k not in HOST_MARKERS}
    env.update(extra)
    return env


def _objects(stdout):
    lines = [l for l in stdout.splitlines() if l.strip()]
    return [json.loads(l) for l in lines]


def _review_with_finding(workspace, env, stub_api):
    ws, repo = workspace
    stub_api.vulns = [STUB_VULN]
    run_hook(ups_payload(repo), env)
    (repo / "app.py").write_text(VULN_PY)
    run_hook(edit_payload(repo, repo / "app.py", VULN_PY), env)
    return run_hook(stop_payload(repo), env)


class TestOtherHost:
    def test_stop_skip_path_prints_only_standard_fields(self, workspace, hook_env):
        ws, repo = workspace
        rc, so, se = run_hook(stop_payload(repo), _env(hook_env, PLUGIN_ROOT=str(ws)))
        assert rc == 0
        assert _objects(so) == [{}]

    def test_stop_finding_keeps_the_block_and_the_guidance(self, workspace, hook_env, stub_api):
        rc, so, se = _review_with_finding(workspace, _env(hook_env, PLUGIN_ROOT="/p"), stub_api)
        (out,) = _objects(so)
        assert set(out) <= STOP_FIELDS, out
        assert out["decision"] == "block"
        assert "command_injection" in out["reason"]
        assert "command_injection" in se

    def test_pattern_warning_keeps_the_guidance(self, workspace, hook_env):
        ws, repo = workspace
        env = _env(hook_env, PLUGIN_ROOT="/p")
        (repo / "app.py").write_text(VULN_PY)
        rc, so, se = run_hook(edit_payload(repo, repo / "app.py", VULN_PY), env)
        assert rc == 0
        (out,) = _objects(so)
        assert set(out) <= POST_TOOL_USE_FIELDS, out
        assert out["hookSpecificOutput"]["additionalContext"]

    def test_kill_switch_path(self, workspace, hook_env):
        ws, repo = workspace
        env = _env(hook_env, PLUGIN_ROOT="/p", SECURITY_GUIDANCE_DISABLE="1")
        rc, so, se = run_hook(stop_payload(repo), env)
        assert rc == 0
        assert all(set(o) <= STOP_FIELDS for o in _objects(so))


class TestClaudeCodeUnchanged:
    @pytest.mark.parametrize("extra", [
        {},
        {"PLUGIN_ROOT": "/p", "CLAUDECODE": "1"},
        {"PLUGIN_ROOT": "/p", "CLAUDE_CODE_ENTRYPOINT": "cli"},
        {"PLUGIN_ROOT": "/p", "SECURITY_GUIDANCE_PORTABLE_OUTPUT": "0"},
    ])
    def test_metrics_and_summary_are_still_sent(self, workspace, hook_env, stub_api, extra):
        rc, so, se = _review_with_finding(workspace, _env(hook_env, **extra), stub_api)
        (out,) = _objects(so)
        assert out["metrics"]["vulns_found"] == 1
        assert out["rewakeSummary"]
        assert out["decision"] == "block"

    def test_forced_on_under_claude_code(self, workspace, hook_env):
        ws, repo = workspace
        env = _env(hook_env, CLAUDECODE="1", SECURITY_GUIDANCE_PORTABLE_OUTPUT="1")
        rc, so, se = run_hook(stop_payload(repo), env)
        assert metrics_of(so) is None and _objects(so) == [{}]
