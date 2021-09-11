import sys
from pathlib import Path
path = Path(__file__).parent.resolve()
parent = path.parents[0]
[sys.path.append(x) for x in map(str, [path, parent]) if x not in sys.path]

import log_config
from config import *
from collections import defaultdict

logger = log_config.get_custom_logger(__name__)


class ReportPool(object):
    def __init__(self):
        self.reports = {}
    
    def report(self, msg):
        ticket = msg['ticket']
        attack_id = msg['attack_id']

        if ticket not in self.reports:
            # Create new report for current ticket
            REPORT = defaultdict(dict)
            REPORT["attack_id"] = attack_id
            REPORT["ticket"] = ticket

            self.reports[ticket] = REPORT
        else:
            REPORT = self.reports[ticket]

        return REPORT

    def delete(self, fd, attack_id):
        if fd in self.reports:
            report = self.reports[fd]
            if attack_id in report:
                report.pop(attack_id)
                logger.info(f"Delete report {fd}/{attack_id}")
                return True
        return False

    def delete_all(self, fd):
        if fd in self.reports:
            logger.debug("Not reachable")
            self.reports.pop(fd)