"""sanitize_for_pandoc(): pdflatex aborts on emoji/symbols, which used to make
export_pdf() silently fall back to the fpdf2 renderer that truncates reports."""
import os

import report_generator as rg


def test_known_symbols_become_ascii():
    out = rg.sanitize_for_pandoc("> ⚠️ note\n- ✅ ok ❌ bad → next “q” ‘s’ — end…")
    assert "⚠" not in out and "️" not in out
    assert out == "> WARNING: note\n- [OK] ok [X] bad -> next \"q\" 's' -- end..."


def test_warning_sign_followed_by_text_gets_a_space():
    assert rg.sanitize_for_pandoc("⚠Scope").startswith("WARNING: Scope")


def test_unknown_emoji_replaced_not_crashing():
    assert rg.sanitize_for_pandoc("ok \U0001F600 done") == "ok ? done"


def test_ascii_accents_markdown_and_newlines_untouched():
    text = "# Title\n\n| a | b |\n|---|---|\n| café | naïve |\n\tindented `code` **bold**\n"
    assert rg.sanitize_for_pandoc(text) == text


def test_output_has_nothing_latex_cannot_handle():
    nasty = "⚠️ ✅ \U0001F680 中文 नमस्ते ​⁠ café"
    out = rg.sanitize_for_pandoc(nasty)
    assert all(ord(c) < 0x180 for c in out)


def test_empty_and_none():
    assert rg.sanitize_for_pandoc("") == ""
    assert rg.sanitize_for_pandoc(None) is None


def test_export_pdf_hands_sanitized_markdown_to_pandoc(tmp_path, monkeypatch):
    """Regression: the markdown file given to pandoc must not contain the raw
    warning emoji (otherwise pdflatex fails and the lossy fallback kicks in)."""
    seen = {}

    def fake_run(cmd, **kw):
        with open(cmd[1], encoding="utf-8") as f:
            seen["md"] = f.read()
        out = cmd[cmd.index("-o") + 1]
        with open(out, "wb") as f:
            f.write(b"%PDF-fake")

        class R:
            returncode = 0
            stderr = ""
        return R()

    monkeypatch.setattr(rg.shutil, "which", lambda name: "/usr/bin/pandoc")
    monkeypatch.setattr(rg.subprocess, "run", fake_run)
    monkeypatch.setattr(rg, "export_pdf_fallback", lambda *a, **k: (_ for _ in ()).throw(AssertionError("fell back")))

    out_path = str(tmp_path / "r.pdf")
    assert rg.export_pdf("# R\n\n- ⚠️ careful\n", out_path) == out_path
    assert "⚠" not in seen["md"] and "WARNING: careful" in seen["md"]
    assert not os.path.exists(out_path + ".tmp.md")                  # temp file cleaned up
