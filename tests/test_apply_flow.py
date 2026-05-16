from __future__ import annotations

import io
import re
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import typer

from coxyz import cli
from coxyz.config import (
    CategoryConfig,
    ComposeTemplateConfig,
    Config,
    PrincipalConfig,
    RuleConfig,
    SettingsConfig,
)
from coxyz.policy import Finding, ServiceReport, Severity, apply_findings
from coxyz.system import CommandExecutionError, CommandRunner


class ApplyFindingsTests(unittest.TestCase):
    def test_creates_missing_dir_without_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "apps" / "svc" / "config"
            finding = Finding(
                path=target,
                rule_name="config_dir",
                severity=Severity.DRIFT,
                fixes=[["mkdir", str(target)]],
            )

            result = apply_findings([finding], dry_run=False)

            self.assertTrue(target.is_dir())
            self.assertIn(["mkdir", "-p", str(target)], result.commands_run)

    def test_deduplicates_duplicate_mkdir_for_same_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "apps" / "svc" / "config"
            finding = Finding(
                path=target,
                rule_name="config_dir",
                severity=Severity.DRIFT,
                fixes=[["mkdir", str(target)], ["mkdir", "-p", str(target)]],
            )

            result = apply_findings([finding], dry_run=True)
            mkdir_target = ["mkdir", "-p", str(target)]
            self.assertEqual(1, sum(1 for cmd in result.commands_run if cmd == mkdir_target))


class ApplyFailureDisplayTests(unittest.TestCase):
    def test_apply_cmd_prints_readable_error_on_shell_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cli.ctx.config = Config(
                root_dir=Path(tmp),
                settings=SettingsConfig(
                    principals={
                        "komodo": PrincipalConfig(name="komodo_runner", kind="group")
                    }
                ),
                categories={"apps": CategoryConfig(user="root", group="root")},
                rules={"category_dir": RuleConfig(mode="750")},
                exclude=[],
                compose_template=ComposeTemplateConfig(
                    default_internal_port=8080,
                    default_timezone="UTC",
                    external_network="proxy",
                ),
            )
            cli.ctx.config_source = None
            cli.ctx.acl_enabled = False
            cli.ctx.principals_available = {"komodo": False}

            drift = Finding(
                path=Path(tmp) / "apps" / "svc" / "config",
                rule_name="config_dir",
                severity=Severity.DRIFT,
                fixes=[["mkdir", "-p", str(Path(tmp) / "apps" / "svc" / "config")]],
            )
            report = ServiceReport(category="apps", service="svc", path=Path(tmp), findings=[drift])

            stderr = io.StringIO()
            with (
                patch("coxyz.cli.resolve_service", return_value=("apps", "svc", Path(tmp))),
                patch("coxyz.cli.audit_category", return_value=Finding(Path(tmp), "category_dir", Severity.OK)),
                patch("coxyz.cli.audit_service", return_value=report),
                patch(
                    "coxyz.cli.apply_findings",
                    side_effect=CommandExecutionError(
                        command=("mkdir", "-p", "/blocked"),
                        returncode=1,
                        stdout="",
                        stderr="Permission denied",
                    ),
                ),
                redirect_stderr(stderr),
            ):
                with self.assertRaises(typer.Exit) as exc:
                    cli.apply_cmd("apps/svc", yes=True)

            self.assertEqual(2, exc.exception.exit_code)
            output = re.sub(r"\x1b\[[0-9;]*m", "", stderr.getvalue())
            self.assertIn("Failed to apply fixes", output)
            self.assertIn("Command", output)
            self.assertIn("/blocked", output)
            self.assertIn("Permission denied", output)


class CommandRunnerTests(unittest.TestCase):
    def test_runner_wraps_calledprocesserror(self) -> None:
        runner = CommandRunner(dry_run=False)

        with self.assertRaises(CommandExecutionError) as exc:
            runner.run(["bash", "-lc", "echo OUT && echo ERR 1>&2 && exit 7"])

        err = exc.exception
        self.assertEqual(("bash", "-lc", "echo OUT && echo ERR 1>&2 && exit 7"), err.command)
        self.assertEqual(7, err.returncode)
        self.assertIn("OUT", err.stdout)
        self.assertIn("ERR", err.stderr)


if __name__ == "__main__":
    unittest.main()
