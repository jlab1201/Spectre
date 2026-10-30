"""report_sections — the deterministic section builders behind report.md.

Split out of report_synthesize.py (Wave 6) with no behaviour change. Each
module owns one report section (or one concern shared by several) plus the
helpers only it uses. ``report_synthesize._merge_report_md`` composes the
``_section_*`` builders in report order; ``report_synthesize`` re-exports
every name, so it remains the public import surface.

Deliberately imports nothing: submodules import each other directly, and
report_validators imports report_sections.verdict, so an eager import here
would risk a cycle.
"""
