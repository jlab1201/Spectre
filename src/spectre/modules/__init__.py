"""Analyzer-module package. Deliberately empty of imports.

Module discovery is `registry.discover()`'s job — filesystem-driven, so
dropping a directory in makes it available with no edits anywhere. This file
used to hold a hand-written `MODULE_REGISTRY` naming 4 of the 8 modules,
which nothing referenced, and it imported those 4 eagerly: `import
spectre.modules.lnk` pulled in memory, evtx, disk and pcap as a side effect.
Keep it import-free so one module's broken dependency stays one module's
problem — see tests/test_recognizer_import_weight.py.
"""
