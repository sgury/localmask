"""Enhancement layer — not included in this build.

The engine calls load() opportunistically; returning None means the
free pipeline (regex + NER + entropy) runs unchanged.
"""

AVAILABLE = False

_NOTICED = False


def load():
    global _NOTICED
    if not _NOTICED:
        _NOTICED = True
        try:
            from ._edition import upgrade_notice
            print(f"[LocalMask] {upgrade_notice('llm_classifier')}")
        except Exception:
            pass
    return None
