"""Acceptance tests for fingerprint matching and safe patch-copy behavior."""

from pathlib import Path

import pytest

from securelens.differ import classify, fingerprint, normalized_snippet
from securelens.fixer import PatchResponse, apply_patches, generate_patch
from securelens.models import Finding, Patch


def make_finding(line, snippet, *, rule="B307", function="calculate", file="app.py"):
    return Finding(id=f"f{line}-{snippet}", tool="bandit", rule_id=rule, file=file, line=line,
                   severity="MEDIUM", message="alert", snippet=snippet,
                   function_name=function, fingerprint="ignored")


def test_fingerprint_masks_literals_and_line_shifts():
    first = make_finding(5, 'result = eval("2 + 3")')
    shifted = make_finding(105, "result   = eval('9 + 8')")

    assert normalized_snippet(first.snippet) == normalized_snippet(shifted.snippet)
    assert fingerprint(first) == fingerprint(shifted)


def test_classify_finds_fixed_remaining_and_new_with_changed_lines():
    before = [
        make_finding(5, "dangerous()", rule="B307", function="first"),
        make_finding(12, "still_bad()", rule="B301", function="second"),
    ]
    after = [
        make_finding(120, "still_bad()", rule="B301", function="second"),
        make_finding(30, "brand_new()", rule="B602", function="third"),
    ]

    result = classify(before, after)

    assert [item.id for item in result.fixed] == [before[0].id]
    assert [item.id for item in result.remaining] == [after[0].id]
    assert [item.id for item in result.new] == [after[1].id]


def test_classify_uses_multiset_matching_for_duplicate_fingerprints():
    before = [make_finding(1, "same()", function="a"), make_finding(2, "same()", function="a")]
    after = [make_finding(8, "same()", function="a")]

    result = classify(before, after)

    assert len(result.remaining) == 1
    assert len(result.fixed) == 1
    assert result.remaining[0].line == 8


class MockLLM:
    def __init__(self, response):
        self.response = response
    def complete(self, *args):
        return self.response


def test_patch_generation_and_application_never_modify_original(tmp_path, monkeypatch):
    project = tmp_path / "demo"
    project.mkdir()
    source = project / "app.py"
    original = "def value():\n    return eval('1 + 1')\n"
    patched = "def value():\n    return 2\n"
    source.write_text(original, encoding="utf-8")
    finding = make_finding(2, "return eval('1 + 1')")
    generated = generate_patch(source, [finding], project_dir=project,
                               llm_client=MockLLM(PatchResponse(patched_code=patched,
                                                                explanation="Remove the unsafe evaluation.")))

    assert generated.file == "app.py"
    assert generated.diff.startswith("--- a/app.py")
    assert finding.id in generated.addressed_finding_ids
    monkeypatch.chdir(tmp_path)
    copy = apply_patches(project, [generated])

    assert source.read_text(encoding="utf-8") == original
    assert (copy / "app.py").read_text(encoding="utf-8") == patched
    assert (copy / ".securelens-patched").is_file()


def test_patch_path_traversal_is_rejected_without_changing_original(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()
    source = project / "app.py"
    original = "print('safe')\n"
    source.write_text(original, encoding="utf-8")
    patch = Patch(file="../outside.py", original_code=original, patched_code="unsafe\n",
                  diff="", explanation="bad", addressed_finding_ids=[])

    with pytest.raises(ValueError, match="Unsafe patch path"):
        apply_patches(project, [patch], workdir=tmp_path / "workdir")

    assert source.read_text(encoding="utf-8") == original


def test_stale_patch_is_rejected_without_changing_original(tmp_path):
    project = tmp_path / "demo"
    project.mkdir()
    source = project / "app.py"
    source.write_text("print('changed')\n", encoding="utf-8")
    patch = Patch(file="app.py", original_code="print('old')\n", patched_code="print('patched')\n",
                  diff="", explanation="stale", addressed_finding_ids=[])

    with pytest.raises(ValueError, match="source changed"):
        apply_patches(project, [patch], workdir=tmp_path / "workdir")
