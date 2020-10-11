# Copyright (C) 2017 Marirs.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging

import imagehash
from PIL import Image

from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)


class Deduplicate(Processing):
    """Deduplicate screenshots."""

    key = "deduplicated_shots"

    @staticmethod
    def is_image(filename):
        img_ext = (".jpg", ".png", ".gif", ".bmp", ".gif")
        f = filename.lower()
        return any(f.endswith(ext) for ext in img_ext)

    def deduplicate_images(self, userpath, hashfunc=imagehash.average_hash):
        """
        Remove duplicate images from a path
        :userpath: path of the image files
        :hashfunc: type of image hashing method
        """
        dd_img_set = []

        images = {}
        for name in sorted(os.listdir(userpath)):
            if not self.is_image(name):
                continue
            img = os.path.join(userpath, name)
            log.debug("Deduplicating image: %r", img)
            h = hashfunc(Image.open(img))
            images.setdefault(h, []).append(img)

        dd_img_set = [os.path.basename(v[0]) for k, v in images.items()]

        # Found that we get slightly more complete images in most cases when
        # getting rid of images with close bit distance.
        # We flip the list back around after prune.
        dd_img_set.sort(reverse=True)

        return dd_img_set

    def run(self):
        """Creates a new key in the report dict for 
        the deduplicated screenshots.
        """
        shots = []
        hashmethod = self.options.hashmethod or "ahash"

        """
        Available hash functions:
            ahash:      Average hash
            phash:      Perceptual hash
            dhash:      Difference hash
            whash-haar: Haar wavelet hash
            whash-db4:  Daubechies wavelet hash
        """
        hashfunc = {
            "ahash": imagehash.average_hash,
            "phash": imagehash.phash,
            "dhash": imagehash.dhash,
            "whash-haar": imagehash.whash,
            "whash-db4": lambda img: imagehash.whash(img, mode="db4"),
        }.get(hashmethod)

        shots_path = os.path.join(self.analysis_path, "shots")
        if os.path.exists(shots_path):
            screenshots = self.deduplicate_images(userpath=shots_path, hashfunc=hashfunc)
            screenshots.sort()
            shots = [screenshot.replace(".jpg", "") for screenshot in screenshots]

        return shots
