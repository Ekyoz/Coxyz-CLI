"""Tests for the ACL model and the audit/apply pipeline."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from coxyz.config import (
    CategoryConfig,
    ComposeTemplateConfig,
    Config,
    PrincipalConfig,
    RuleConfig,
    SettingsConfig,
)
from coxyz.policy import (
    Severity,
    acl_set_spec,
    apply_findings,
    audit_service,
    desired_acl,
)
from coxyz.system import (
    Acl,
    detect_acl_support,
    mode_to_perms,
    normalize_perms,
    octal_digit_to_perms,
    perms_to_symbolic,
    read_acl,
    union_perms,
)

# A principal that resolves on any Linux host, used as a stand-in for komodo.
PRINCIPAL_GROUP = "root"


def _make_config(root: Path, owner_user: str, owner_group: str) -> Config:
    return Config(
        root_dir=root,
        settings=SettingsConfig(
            principals={"komodo": PrincipalConfig(name=PRINCIPAL_GROUP, kind="group")}
        ),
        categories={"apps": CategoryConfig(user=owner_user, group=owner_group)},
        rules={
            "category_dir": RuleConfig(mode="750", acl={"komodo": "rx"}),
            "service_dir": RuleConfig(mode="750", acl={"komodo": "rx"}),
            "compose_file": RuleConfig(mode="660", acl={"komodo": "rw"}),
            "config_dir": RuleConfig(mode="750", acl={"komodo": "x"}),
            "data_dir": RuleConfig(mode="750", acl=None, audit_only=True),
            "env_file": RuleConfig(mode="600", owner="root:root", acl=None, audit_only=True),
        },
        exclude=[],
        compose_template=ComposeTemplateConfig(
            default_internal_port=8080, default_timezone="UTC", external_network="net",
        ),
    )


class PermHelperTests(unittest.TestCase):
    def test_octal_digit_to_perms(self) -> None:
        self.assertEqual("rwx", octal_digit_to_perms(7))
        self.assertEqual("rx", octal_digit_to_perms(5))
        self.assertEqual("", octal_digit_to_perms(0))

    def test_mode_to_perms(self) -> None:
        self.assertEqual(("rwx", "rx", ""), mode_to_perms("750"))
        self.assertEqual(("rw", "rw", ""), mode_to_perms("660"))

    def test_normalize_perms_is_order_independent(self) -> None:
        self.assertEqual("rx", normalize_perms("r-x"))
        self.assertEqual("rwx", normalize_perms("xrw"))
        self.assertEqual("", normalize_perms("---"))

    def test_perms_to_symbolic(self) -> None:
        self.assertEqual("r-x", perms_to_symbolic("rx"))
        self.assertEqual("---", perms_to_symbolic(""))
        self.assertEqual("rwx", perms_to_symbolic("rwx"))

    def test_union_perms(self) -> None:
        self.assertEqual("rwx", union_perms("rx", "rw"))
        self.assertEqual("rx", union_perms("rx", "x", ""))


class AclSpecTests(unittest.TestCase):
    def test_acl_set_spec_encodes_mode_and_named_entry(self) -> None:
        cfg = _make_config(Path("/srv/docker"), "svc", "svc")
        spec = acl_set_spec(cfg.rule("service_dir"), cfg)
        self.assertEqual(f"u::rwx,g::r-x,o::---,g:{PRINCIPAL_GROUP}:r-x", spec)

    def test_desired_acl_mask_is_union_of_group_and_named(self) -> None:
        cfg = _make_config(Path("/srv/docker"), "svc", "svc")
        # config_dir: group r-x, komodo --x  ->  mask must be r-x.
        acl = desired_acl(cfg.rule("config_dir"), cfg)
        self.assertEqual("rx", acl.mask)
        self.assertEqual("x", acl.named[("group", PRINCIPAL_GROUP)])


class AclFixPlanningTests(unittest.TestCase):
    """The fix for an ACL path must never be a chmod (it would clobber the mask)."""

    def test_acl_drift_is_fixed_by_a_single_setfacl_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            if not detect_acl_support(Path(tmp)):
                self.skipTest("filesystem has no ACL support")
            cfg = _make_config(Path(tmp), _self_user(), _self_group())
            svc = Path(tmp) / "apps" / "svc"
            svc.mkdir(parents=True)
            (svc / "config").mkdir()
            (svc / "data").mkdir()
            (svc / "compose.yaml").write_text("services: {}\n")

            report = audit_service(
                cfg, "apps", "svc", acl_enabled=True,
                principals_available={"komodo": True},
            )
            svc_finding = next(f for f in report.findings if f.rule_name == "service_dir")
            self.assertIs(Severity.DRIFT, svc_finding.severity)
            self.assertTrue(svc_finding.fixes)
            for command in svc_finding.fixes:
                self.assertNotEqual("chmod", command[0],
                                    "ACL paths must not be fixed with chmod")


class AclApplyIntegrationTests(unittest.TestCase):
    """Apply real setfacl and verify effective rights are never restricted."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        if not detect_acl_support(self.root):
            self.tmp.cleanup()
            self.skipTest("filesystem has no ACL support")
        self.cfg = _make_config(self.root, _self_user(), _self_group())
        self.svc = self.root / "apps" / "svc"
        self.svc.mkdir(parents=True)
        (self.svc / "config").mkdir()
        (self.svc / "data").mkdir()
        (self.svc / "compose.yaml").write_text("services: {}\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _audit_drifts(self) -> list:
        report = audit_service(
            self.cfg, "apps", "svc", acl_enabled=True,
            principals_available={"komodo": True},
        )
        return [f for f in report.findings if f.severity is Severity.DRIFT]

    def test_apply_leaves_no_effective_restriction(self) -> None:
        # A too-narrow mask is the exact bug: the entry says rwx, the mask r--.
        subprocess.run(
            ["setfacl", "-m", f"g:{PRINCIPAL_GROUP}:rwx", "-m", "m:r", str(self.svc)],
            check=True,
        )
        apply_findings(self._audit_drifts(), dry_run=False)

        out = subprocess.run(
            ["getfacl", "-pc", str(self.svc)], capture_output=True, text=True,
        ).stdout
        self.assertNotIn("#effective", out,
                         "mask must not restrict any ACL entry after apply")

        acl = read_acl(self.svc)
        assert acl is not None
        self.assertEqual("rx", acl.named[("group", PRINCIPAL_GROUP)])
        self.assertEqual("rx", acl.mask)

    def test_apply_is_idempotent(self) -> None:
        subprocess.run(["chmod", "700", str(self.svc)], check=True)
        apply_findings(self._audit_drifts(), dry_run=False)
        self.assertEqual([], self._audit_drifts(), "second audit must find no drift")

    def test_audit_detects_narrow_mask_only(self) -> None:
        # Set the correct ACL, then break only the mask.
        subprocess.run(
            ["setfacl", "-k", "--set", acl_set_spec(self.cfg.rule("service_dir"), self.cfg),
             str(self.svc)],
            check=True,
        )
        subprocess.run(["setfacl", "-m", "m:r", str(self.svc)], check=True)

        svc_finding = next(
            f for f in self._audit_drifts() if f.rule_name == "service_dir"
        )
        self.assertTrue(any("mask" in issue for issue in svc_finding.issues))


def _self_user() -> str:
    import getpass
    return getpass.getuser()


def _self_group() -> str:
    import grp
    import os
    return grp.getgrgid(os.getgid()).gr_name


if __name__ == "__main__":
    unittest.main()
