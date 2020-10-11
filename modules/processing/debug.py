# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)


class Debug(Processing):
    """Analysis debug information."""

    key = "debug"

    def run(self):
        """Run debug analysis.
        @return: debug information dict.
        """
        debug = {"log": "", "errors": []}

        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "rt", encoding="utf-8") as f:
                    debug["log"] = f.read()
            except ValueError as e:
                raise CuckooProcessingError("Error decoding %s: %s" % (self.log_path, e))
            except OSError as e:
                raise CuckooProcessingError("Error opening %s: %s" % (self.log_path, e))

        for error in Database().view_errors(int(self.task["id"])):
            debug["errors"].append(error.message)

        return debug
