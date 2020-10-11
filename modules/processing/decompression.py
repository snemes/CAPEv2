# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import glob
import zipfile
import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)


class Decompression(Processing):
    """Decompresses analysis artifacts that have been compressed by the
    compression reporting module so re-analysis can be performed."""

    order = 0
    key = "decompression"

    def extract(self, srcpath, dstpath):
        log.debug("Extracting %r to %r", srcpath, dstpath)
        try:
            with zipfile.ZipFile(srcpath, "r") as zf:
                zf.extractall(path=dstpath)
            os.remove(srcpath)
        except Exception as e:
            raise CuckooProcessingError("Error extracting ZIP: %s", e)

    def run(self):
        filepath = self.memory_path + ".zip"
        if os.path.exists(filepath):
            self.extract(filepath, self.analysis_path)

        for filepath in glob.iglob(os.path.join(self.pmemory_path, "*.zip")):
            self.extract(filepath, self.pmemory_path)

        return []
