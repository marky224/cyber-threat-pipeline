"""CISA Known Exploited Vulnerabilities catalog: validate one download. Pure, no I/O.

The catalog is untrusted input, accepted whole or not at all. ``parse`` returns
a ``KevCatalog`` only when the body:

- parses as one JSON object with ``catalogVersion`` (1-32 characters),
  ``dateReleased`` (a timestamp with a time zone), ``count`` (an integer of at
  least 1) and ``vulnerabilities`` (a list of exactly ``count`` entries);
- gives every entry a ``cveID`` matching ``CVE_ID_PATTERN`` and a ``dateAdded``
  date, with no ``cveID`` twice;
- keeps ``vendorProject``, ``product`` and ``vulnerabilityName`` to 500
  characters and ``knownRansomwareCampaignUse`` to 32 (each optional), after
  control characters become spaces and whitespace runs one space.

Types are strict: a number where text belongs fails, and so does a string where
``count`` belongs. Other keys (``shortDescription``, ``requiredAction``,
``dueDate``, ``notes``, ``cwes``, ``forensicTriage``, anything CISA adds later)
are ignored and not stored. ``check_shrink`` refuses a catalog with under 90%
of the entries in the stored snapshot. Failures raise ``FeedInvalid`` with a
short reason that never quotes feed content.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Annotated, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from cyber_threat_pipeline.enrichment import CVE_ID_PATTERN, FeedInvalid

KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # CISA's GitHub mirror, synced with cisa.gov within minutes; tried only if
    # cisa.gov fails or serves something invalid.
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
MAX_BYTES = 10 * 1024 * 1024  # ~1.8 MB for 1,764 entries on 2026-10-29
SHRINK_FLOOR = 0.9

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(value: object) -> object:
    """Control characters become spaces; whitespace runs collapse; ends trimmed."""
    if isinstance(value, str):
        return " ".join(_CONTROL.sub(" ", value).split())
    return value


CveId = Annotated[str, StringConstraints(pattern=CVE_ID_PATTERN)]
_Name = Annotated[str, BeforeValidator(_clean), StringConstraints(max_length=500)]
_Label = Annotated[str, BeforeValidator(_clean), StringConstraints(max_length=32)]
_STRICT = ConfigDict(strict=True, extra="ignore", frozen=True)


class KevEntry(BaseModel):
    """One catalog entry, reduced to the fields the pipeline stores."""

    model_config = _STRICT

    cve_id: CveId = Field(alias="cveID")
    date_added: date = Field(alias="dateAdded")
    vendor_project: _Name | None = Field(default=None, alias="vendorProject")
    product: _Name | None = Field(default=None, alias="product")
    vulnerability_name: _Name | None = Field(default=None, alias="vulnerabilityName")
    known_ransomware_campaign_use: _Label | None = Field(
        default=None, alias="knownRansomwareCampaignUse"
    )


class KevCatalog(BaseModel):
    """A whole validated catalog download."""

    model_config = _STRICT

    catalog_version: Annotated[str, StringConstraints(min_length=1, max_length=32)] = Field(
        alias="catalogVersion"
    )
    released_at: AwareDatetime = Field(alias="dateReleased")
    count: int = Field(ge=1)
    entries: tuple[KevEntry, ...] = Field(alias="vulnerabilities")

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if len(self.entries) != self.count:
            raise ValueError(f"count is {self.count} but {len(self.entries)} entries arrived")
        duplicates = len(self.entries) - len({e.cve_id for e in self.entries})
        if duplicates:
            raise ValueError(f"{duplicates} duplicate cveID(s)")
        return self


def parse(raw: bytes) -> KevCatalog:
    """Validate one catalog download, or raise ``FeedInvalid``."""
    try:
        return KevCatalog.model_validate_json(raw)
    except ValidationError as e:
        raise FeedInvalid(f"KEV catalog rejected: {_first_problem(e)}") from None


def check_shrink(catalog: KevCatalog, stored_entries: int) -> None:
    """Refuse a catalog that lost more than 10% of the stored snapshot's entries."""
    if len(catalog.entries) < SHRINK_FLOOR * stored_entries:
        raise FeedInvalid(
            f"KEV catalog rejected: {len(catalog.entries)} entries, under 90% of the"
            f" {stored_entries} stored"
        )


def _first_problem(e: ValidationError) -> str:
    """The error count and the first error's location and message, without its input."""
    errors = e.errors(include_url=False, include_context=False, include_input=False)
    first = errors[0]
    where = ".".join(str(part) for part in first["loc"]) or "body"
    return f"{len(errors)} problem(s); first at {where}: {first['msg']}"
