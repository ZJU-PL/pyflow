# Security checker metrics
import logging

LOG = logging.getLogger(__name__)


class Metrics:
    def __init__(self):
        self.files = 0
        self.lines = 0
        self.nosec = 0
        self.skipped = 0
        self.issues = 0
        self.issues_by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        self.issues_by_confidence = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

    def begin(self, filename):
        """Begin processing a file"""
        self.files += 1
        LOG.debug("Processing file: %s", filename)

    def count_locs(self, lines):
        """Count lines of code"""
        self.lines += len(lines)

    def count_issues(self, scores_list):
        """Count issues from scores"""
        for scores in scores_list:
            if scores and isinstance(scores, dict):
                for sev_idx, count in enumerate(scores["SEVERITY"]):
                    if count > 0:
                        sev = ["UNDEFINED", "LOW", "MEDIUM", "HIGH"][sev_idx]
                        if sev in self.issues_by_severity:
                            self.issues_by_severity[sev] += count
                            self.issues += count

                for conf_idx, count in enumerate(scores["CONFIDENCE"]):
                    if count > 0:
                        conf = ["UNDEFINED", "LOW", "MEDIUM", "HIGH"][conf_idx]
                        if conf in self.issues_by_confidence:
                            self.issues_by_confidence[conf] += count

    def note_nosec(self):
        """Note a nosec comment"""
        self.nosec += 1

    def note_skipped_test(self):
        """Note a skipped test"""
        self.skipped += 1

    def aggregate(self):
        """Aggregate final metrics"""
        LOG.debug("Final metrics: %s", self.__dict__)
