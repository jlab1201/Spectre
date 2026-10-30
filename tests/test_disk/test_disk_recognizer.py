"""Track B1: disk recognizer signature coverage."""

from spectre.modules.disk.recognizer import RECOGNIZERS, _sniff

_R = RECOGNIZERS[0]


def _f(tmp_path, name, content):
    p = tmp_path / name
    p.write_bytes(content)
    return p


def test_vmdk_sparse_header_recognized(tmp_path):
    p = _f(tmp_path, "disk.vmdk", b"KDMV" + b"\x00" * 1024)
    assert _sniff(p) is True
    assert _R.match(p, "data") > 0


def test_vmdk_text_descriptor_recognized(tmp_path):
    p = _f(tmp_path, "disk.vmdk",
           b"# Disk DescriptorFile\nversion=1\n" + b"\x00" * 64)
    assert _sniff(p) is True


def test_aff_recognized(tmp_path):
    p = _f(tmp_path, "disk.aff", b"AFF\x00" + b"\x00" * 64)
    assert _sniff(p) is True


def test_gpt_without_protective_mbr_recognized(tmp_path):
    blob = bytearray(b"\x00" * 1024)
    blob[512:520] = b"EFI PART"
    p = _f(tmp_path, "disk.img", bytes(blob))
    assert _sniff(p) is True


def test_mbr_still_recognized(tmp_path):
    blob = bytearray(b"\x00" * 512)
    blob[510:512] = b"\x55\xaa"
    p = _f(tmp_path, "disk.dd", bytes(blob))
    assert _sniff(p) is True


def test_ewf_still_recognized(tmp_path):
    p = _f(tmp_path, "disk.e01", b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 64)
    assert _sniff(p) is True


def test_garbage_with_disk_extension_rejected(tmp_path):
    p = _f(tmp_path, "notdisk.dd", b"just some text" + b"\x00" * 1024)
    assert _sniff(p) is False
    assert _R.match(p, "ASCII text") == 0.0
