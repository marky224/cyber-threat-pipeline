"""CVE enrichment: CISA KEV catalog and FIRST EPSS scores into Neon's raw schema.

``make enrich`` (``python -m cyber_threat_pipeline.enrichment``) runs after
ingest. Both feeds are untrusted input: ``fetch`` bounds every download, and
``kev`` / ``epss`` accept a response whole or not at all.
"""

# A CVE id as the enrichment step reads, sends and stores it. The sequence
# number is capped at 15 digits (24 characters in all), so one absurd OTX value
# can't push an EPSS request past the API's 2000-character `cve` limit. dbt's
# mart_cve_enrichment and load.read_inputs use the same pattern; the raw tables'
# CHECK is the looser backstop.
CVE_ID_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,15}$"


class FeedInvalid(ValueError):
    """A feed response broke a validation rule; it is dropped whole."""
