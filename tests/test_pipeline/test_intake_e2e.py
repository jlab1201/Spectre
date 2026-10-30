"""Track B1 e2e: a directory of mixed evidence flows through Phase 0
with nothing silently lost."""
from pathlib import Path

from spectre.pipeline.case_setup import setup_case

_PCAP_HDR = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
_EVTX_HDR = b"ElfFile\x00" + b"\x00" * 4088


def test_mixed_directory_intake(tmp_path, capsys):
    dump = tmp_path / "dump"
    (dump / "host1").mkdir(parents=True)
    (dump / "host2").mkdir()
    (dump / "host1" / "Security.evtx").write_bytes(_EVTX_HDR)
    (dump / "host2" / "Security.evtx").write_bytes(_EVTX_HDR + b"\x01")
    (dump / "traffic.pcap").write_bytes(_PCAP_HDR)
    (dump / "mystery.xyz").write_bytes(b"\x00\x01\x02unknowable")
    (dump / "empty.log").write_bytes(b"")

    result = setup_case(name="intake-e2e", profile="auto",
                        evidence_paths=[str(dump)],
                        cases_dir=str(tmp_path / "cases"))
    case_dir = Path(result["case_dir"])
    import yaml
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text())

    # Files only: evidence/derived/ is the (writable) carve dir W3-2 creates
    # before evidence/ itself is locked 0555.
    staged = sorted(p.name for p in (case_dir / "evidence").iterdir() if p.is_file())
    assert ((case_dir / "evidence").stat().st_mode & 0o777) == 0o555
    # 4 files staged (2 evtx with distinct names, pcap, mystery); empty skipped
    assert len(staged) == 4, staged
    assert sum(1 for n in staged if n.startswith("Security")) == 2

    triage = manifest["triage"]
    statuses = {Path(k).name.split("__")[0]: v["status"] for k, v in triage.items()}
    assert statuses["traffic.pcap"] in ("RECOGNIZED", "EXTRACTOR_PENDING")
    assert statuses["mystery.xyz"] == "UNRECOGNIZED"
    assert any(s["reason"] == "empty file (0 bytes)"
               for s in manifest["intake_skipped"])
