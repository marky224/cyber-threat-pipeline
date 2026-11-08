"""The /cves page shows KEV feed text only as escaped text.

KEV's vendor, product and vulnerability name are feed text: ``kev.parse``
strips control characters and caps their length, nothing more, so they can
hold ``<`` and ``>``. Rows render client-side from parquet, so a grep of the
built HTML would pass without proving anything; the page source decides. In
Evidence's core-components 5.4.2, a DataTable cell renders
``{formatValue(...)}``, Svelte text interpolation, which escapes; only a column
with ``contentType='html'`` renders ``{@html row[column.id]}``
(``TableRow.svelte:311-314``). A ``contentType`` of link or image puts a row
value into an ``href`` or ``src`` (``TableRow.svelte:142-158``), and so does
the DataTable's ``link=`` (``TableRow.svelte:319-322``).
"""

from __future__ import annotations

import re
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "reporting" / "pages" / "cves.md"

# contentType=html, ="link", ='image', {"html"}, ... in any quoting.
_RAW_CONTENT = re.compile(r"""contentType\s*=\s*\{?\s*["']?\s*(html|link|image)\b""", re.I)
_ROW_LINK = re.compile(r"<(?:DataTable|Column)\b[^>]*\blink\s*=", re.I)


def test_cves_page_renders_kev_text_only_as_escaped_text() -> None:
    page = PAGE.read_text()
    # The page does show the KEV text, as DataTable columns.
    for column in ("kev_vendor_project", "kev_product", "kev_vulnerability_name"):
        assert re.search(rf"<Column\s+id={column}\b", page), column
    assert not re.search(r"\{\s*@html", page)
    assert not _RAW_CONTENT.search(page)
    assert not _ROW_LINK.search(page)
