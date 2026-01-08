from collections import defaultdict
from typing import Dict, Iterable

from .models import Finding


def diff_findings(
    current: Iterable[Finding], previous: Iterable[Finding]
) -> Dict[str, list[Finding]]:
    """Return new/fixed/still-present buckets keyed by finding dedupe_key."""
    prev_by_key = {f.dedupe_key: f for f in previous}
    cur_by_key = {f.dedupe_key: f for f in current}

    result: Dict[str, list[Finding]] = defaultdict(list)
    for key, finding in cur_by_key.items():
        if key in prev_by_key:
            result["still_present"].append(finding)
        else:
            result["new"].append(finding)
    for key, finding in prev_by_key.items():
        if key not in cur_by_key:
            result["fixed"].append(finding)
    return result
