"""The threat-data analyst: plain-English questions over the 11 marts.

A question becomes one model-written query, which ``guard`` checks and renders
again from its own parse before anything runs it. ``gold.toml`` holds the gold
set: questions with hand-checked SQL, scored by comparing query results.

The private phase 08 spec governs this subpackage.
"""
