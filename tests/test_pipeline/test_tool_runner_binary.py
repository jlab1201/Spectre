"""run_tool output_format="binary" must preserve raw bytes."""
from pathlib import Path

from spectre.pipeline.tool_runner import run_tool

# bytes that break text-mode roundtrips: invalid UTF-8 + CR/LF + NUL
_RAW = b"\x00\xff\xfe\x01ElfFile\x00\r\n\x80\x81binary"


def _case(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    return str(case)


def test_binary_output_preserves_raw_bytes(tmp_path):
    case = _case(tmp_path)
    blob = tmp_path / "blob.bin"
    blob.write_bytes(_RAW)
    out = str(tmp_path / "out.bin")
    handle = run_tool(
        case_dir=case, tool_name="cat", tool_version="coreutils",
        command=["cat", str(blob)],
        params={"artifact_type": "test", "phase": "extraction"},
        output_path=out, output_format="binary",
    )
    assert handle["result"] == "success"
    assert Path(out).read_bytes() == _RAW
    assert handle["size_bytes"] == len(_RAW)


def test_text_output_unchanged(tmp_path):
    case = _case(tmp_path)
    f = tmp_path / "t.txt"
    f.write_text("hello\nworld\n")
    out = str(tmp_path / "out.txt")
    handle = run_tool(
        case_dir=case, tool_name="cat", tool_version="coreutils",
        command=["cat", str(f)],
        params={"artifact_type": "test", "phase": "extraction"},
        output_path=out, output_format="text",
    )
    assert Path(out).read_text() == "hello\nworld\n"
    assert handle["line_count"] == 2


def _run_py(tmp_path, code, fmt="text", timeout=60):
    case = _case(tmp_path)
    out = str(tmp_path / "o.out")
    import sys
    h = run_tool(
        case_dir=case, tool_name="py", tool_version="x",
        command=[sys.executable, "-c", code],
        params={"artifact_type": "test", "phase": "extraction"},
        output_path=out, output_format=fmt, timeout=timeout,
    )
    return h, Path(out)


def test_text_output_streamed_and_partial_kept_on_failure(tmp_path):
    h, out = _run_py(tmp_path, "print('a'*10); import sys; sys.stderr.write('boom'); sys.exit(3)")
    assert h["exit_code"] == 3
    assert out.read_text() == "a" * 10 + "\n"
    assert "boom" in h["stderr"]


def test_text_crlf_and_lone_cr_normalized_like_universal_newlines(tmp_path):
    code = "import sys; sys.stdout.buffer.write(b'a\\r\\nb\\rc\\n\\r\\nd\\r')"
    h, out = _run_py(tmp_path, code)
    assert out.read_bytes() == b"a\nb\nc\n\nd\n"
    assert h["line_count"] == 5


def test_text_crlf_split_across_chunk_boundary(tmp_path, monkeypatch):
    from spectre.pipeline import tool_runner as tr
    p = tmp_path / "x"
    p.write_bytes(b"ab\r\ncd\r\r\nef\r")
    tr._normalize_newlines_inplace(str(p), chunk_size=3)
    assert p.read_bytes() == b"ab\ncd\n\nef\n"


def test_text_invalid_utf8_kept_and_does_not_crash(tmp_path):
    code = "import sys; sys.stdout.buffer.write(b'{\"a\":1}\\n\\xff\\xfe\\n')"
    h, out = _run_py(tmp_path, code, fmt="json")
    assert out.read_bytes() == b'{"a":1}\n\xff\xfe\n'
    assert h["line_count"] == 2


def test_timeout_keeps_partial_output(tmp_path):
    code = "import sys,time; print('part\\r\\n', flush=True); time.sleep(30)"
    h, out = _run_py(tmp_path, code, timeout=2)
    assert h["result"] == "error" and h["exit_code"] == -1
    assert out.read_bytes().startswith(b"part\n")


def test_missing_executable_leaves_no_output_stub(tmp_path):
    import pytest

    case = _case(tmp_path)
    out = tmp_path / "derived" / "carve.bin"
    with pytest.raises(OSError):
        run_tool(
            case_dir=case, tool_name="nope", tool_version="0",
            command=["/nonexistent/definitely-not-a-tool"],
            params={"artifact_type": "test", "phase": "extraction"},
            output_path=str(out), output_format="binary",
        )
    assert not out.exists()


def test_newline_normalization_preserves_file_mode(tmp_path):
    import os
    from spectre.pipeline.tool_runner import _normalize_newlines_inplace

    p = tmp_path / "t.txt"
    p.write_bytes(b"a\r\nb\rc\n")
    os.chmod(p, 0o640)
    _normalize_newlines_inplace(str(p))
    assert p.read_bytes() == b"a\nb\nc\n"
    assert (os.stat(p).st_mode & 0o777) == 0o640
    assert [x.name for x in tmp_path.iterdir()] == ["t.txt"]
