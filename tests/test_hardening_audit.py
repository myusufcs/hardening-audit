"""Uji hardening-audit: registry, model, util, renderer, dan audit end-to-end."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hardening_audit import registry, report, util  # noqa: E402
from hardening_audit.model import Finding, Report, Severity, Status  # noqa: E402


class TestRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        registry.load_all()

    def test_semua_cek_terdaftar(self):
        self.assertGreaterEqual(len(registry.ALL_CHECKS), 20)
        codes = [c.CODE for c in registry.ALL_CHECKS]
        self.assertEqual(len(codes), len(set(codes)), "ada kode pemeriksaan duplikat")

    def test_filter_only_dan_skip(self):
        only_ssh = registry.select(["ssh"], None)
        self.assertTrue(only_ssh)
        self.assertTrue(all(c.CATEGORY == "ssh" or c.CODE == "ssh" for c in only_ssh))

        satu = registry.ALL_CHECKS[0].CODE
        hasil = registry.select([satu], None)
        self.assertEqual([c.CODE for c in hasil], [satu])
        self.assertEqual(registry.select(None, [satu]), [] or
                         [c for c in registry.select(None, [satu]) if c.CODE != satu])

    def test_kode_pemeriksaan_unik_dan_terpilih(self):
        semua = registry.select(None, None)
        self.assertEqual(len(semua), len(registry.ALL_CHECKS))
        self.assertEqual(semua, sorted(semua, key=lambda c: (c.CATEGORY, c.CODE)))


class TestModel(unittest.TestCase):
    def _report(self) -> Report:
        r = Report(hostname="h", platform="p", started="t")
        r.findings = [
            Finding("a", "A", Status.PASS, Severity.INFO),
            Finding("b", "B", Status.FAIL, Severity.CRITICAL),
            Finding("c", "C", Status.WARN, Severity.LOW),
            Finding("d", "D", Status.SKIP, Severity.INFO),
        ]
        return r

    def test_skor_mengabaikan_skip(self):
        r = self._report()
        self.assertEqual(r.applicable, 3)
        self.assertEqual(r.score, 33)           # 1 dari 3 lolos

    def test_prioritas_urut_keparahan(self):
        r = self._report()
        urut = [f.code for f in r.by_severity()]
        self.assertEqual(urut, ["b", "c"])

    def test_serialisasi(self):
        d = self._report().as_dict()
        self.assertEqual(d["summary"]["FAIL"], 1)
        json.dumps(d)                            # harus bisa diserialkan


class TestUtil(unittest.TestCase):
    def test_parse_sshd_config(self):
        with tempfile.TemporaryDirectory() as td:
            main = Path(td) / "sshd_config"
            main.write_text(
                "# komentar\n"
                "PermitRootLogin yes\n"
                "PasswordAuthentication no\n"
                "Port 22\n"
                "\tMaxAuthTries\t4\n"
            )
            conf = util.sshd_effective(main, include_dir=None)
            self.assertEqual(conf["permitrootlogin"], "yes")
            self.assertEqual(conf["passwordauthentication"], "no")
            self.assertEqual(conf["maxauthtries"], "4")

    def test_include_dir_dan_opsi_pertama_menang(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "sshd_config").write_text("PermitRootLogin yes\n")
            inc = d / "sshd_config.d"
            inc.mkdir()
            (inc / "10-hard.conf").write_text("PermitRootLogin no\nLoginGraceTime 30\n")
            conf = util.sshd_effective(d / "sshd_config", include_dir=inc)
            self.assertEqual(conf["permitrootlogin"], "yes")   # main file menang
            self.assertEqual(conf["logingracetime"], "30")


class TestReport(unittest.TestCase):
    def _report(self) -> Report:
        r = Report(hostname="uji", platform="linux", started="a", finished="b")
        r.findings = [Finding("x.y", "Ada temuan", Status.FAIL, Severity.HIGH,
                              "detail penting", "lakukan hal ini", category="kategori")]
        return r

    def test_text_memuat_temuan_dan_skor(self):
        t = report.to_text(self._report())
        self.assertIn("Ada temuan", t)
        self.assertIn("lakukan hal ini", t)
        self.assertIn("LAPORAN HARDENING", t)

    def test_markdown_memuat_tabel(self):
        md = report.to_markdown(self._report())
        self.assertIn("| Prioritas |", md)
        self.assertIn("`x.y`", md)

    def test_json_valid(self):
        d = json.loads(report.to_json(self._report()))
        self.assertEqual(d["findings"][0]["severity"], "HIGH")

    def test_write_semua_format(self):
        with tempfile.TemporaryDirectory() as td:
            files = report.write(Path(td), self._report(), ["text", "md", "json"])
            self.assertEqual(len(files), 3)
            for f in files:
                self.assertTrue(f.is_file() and f.stat().st_size > 0)


class TestAuditEndToEnd(unittest.TestCase):
    def test_audit_jalan_di_mesin_ini(self):
        """Semua pemeriksaan harus jalan tanpa exception di lingkungan apa pun."""
        from hardening_audit.cli import run_audit, build_parser
        with tempfile.TemporaryDirectory() as td:
            args = build_parser().parse_args(["--out", td, "--format", "json"])
            code = run_audit(args)
            self.assertIn(code, (0, 1))

            hasil = list(Path(td).glob("*.json"))
            self.assertEqual(len(hasil), 1)
            data = json.loads(hasil[0].read_text())
            self.assertGreaterEqual(len(data["findings"]), 20)
            self.assertEqual(data["errors"], [], f"ada error: {data['errors']}")

    def test_filter_only_menghasilkan_satu_kategori(self):
        from hardening_audit.cli import run_audit, build_parser
        with tempfile.TemporaryDirectory() as td:
            args = build_parser().parse_args(["--out", td, "--format", "json", "--only", "ssh"])
            run_audit(args)
            data = json.loads(next(Path(td).glob("*.json")).read_text())
            self.assertTrue(data["findings"])
            self.assertTrue(all(f["category"] == "ssh" for f in data["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
