# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# Based on work of Xabier Ugarte-Pedrero
#  https://github.com/Cisco-Talos/pyrebox/blob/python3migration/pyrebox/volatility_glue.py

# Vol3 docs - https://volatility3.readthedocs.io/en/latest/index.html
import os
import logging

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooProcessingError

try:
    import volatility.plugins
    import volatility.symbols
    from volatility import framework
    from volatility.cli import text_renderer
    from volatility.framework import automagic, constants, contexts, exceptions, interfaces, plugins, configuration
    from volatility.framework.configuration import requirements
    from typing import Any, Dict, List, Optional, Tuple, Union, Type
    from volatility.framework import interfaces, constants
    from volatility.framework.configuration import requirements

    # from volatility.plugins.windows import pslist
    HAVE_VOLATILITY = True
except Exception as e:
    HAVE_VOLATILITY = False

log = logging.getLogger(__name__)

# Log everything:
# log.setLevel(1)

# Log only Warnings
# log.setLevel(logging.WARNING)

# Trim the console down by default
# console = logging.StreamHandler()
# console.setLevel(logging.WARNING)
# formatter = logging.Formatter('%(levelname)-8s %(name)-12s: %(message)s')
# console.setFormatter(formatter)
# log.addHandler(console)


class VolatilityAPI(object):
    def __init__(self, memdump):
        self.context = None
        self.automagics = None
        self.base_config_path = "plugins"
        # Instance of the plugin
        self.volatility_interface = None
        if not memdump.startswith("file:///") and os.path.exists(memdump):
            self.memdump = "file:///" + memdump
        else:
            self.memdump = memdump

    def init(self, plugin_class, memdump):
        """ Module which initialize all volatility 3 internals
        @param plugin_class: plugin class. Ex. windows.pslist.PsList
        @param memdump: path to memdump. Ex. file:///home/vol3/memory.dmp
        @return: Volatility3 interface.

        """

        volatility.framework.require_interface_version(1, 0, 0)
        # Set the PARALLELISM
        # constants.PARALLELISM = constants.Parallelism.Multiprocessing
        # constants.PARALLELISM = constants.Parallelism.Threading
        constants.PARALLELISM = constants.Parallelism.Off

        # Do the initialization
        self.context = contexts.Context()  # Construct a blank context
        # Will not log as console's default level is WARNING
        failures = framework.import_files(volatility.plugins, True)

        self.automagics = automagic.available(self.context)
        # Initialize the list of plugins in case the plugin needs it
        plugin_list = framework.list_plugins()

        self.context.config["automagic.LayerStacker.single_location"] = self.memdump

        self.automagics = automagic.choose_automagic(self.automagics, plugin_class)
        volatility_interface = plugins.construct_plugin(self.context, self.automagics, plugin_class, self.base_config_path, None, None)

        return volatility_interface


class VolatilityManager(object):
    """Handle several volatility results."""

    key = "memory"

    def __init__(self, memfile):
        self.mask_pid = []
        self.taint_pid = set()
        self.memfile = memfile

        conf_path = os.path.join(CUCKOO_ROOT, "conf", "memory.conf")
        if not os.path.exists(conf_path):
            log.error("Configuration file memory.conf not found")
            self.voptions = False
            return

        self.voptions = Config("memory")

        if isinstance(self.voptions.mask.pid_generic, int):
            self.mask_pid.append(self.voptions.mask.pid_generic)
        else:
            for pid in self.voptions.mask.pid_generic.split(","):
                pid = pid.strip()
                if pid:
                    self.mask_pid.append(int(pid))

        self.no_filter = not self.voptions.mask.enabled

    def run(self, manager=None, vm=None):
        results = dict()

        # Exit if options were not loaded.
        if not self.voptions:
            return

        self.do_strings()
        self.cleanup()
        
        if not self.voptions.basic.delete_memdump:
            results['memory_path'] = self.memfile
        if self.voptions.basic.dostrings:
            results['memory_strings_path'] = self.memfile + ".strings"

        return results

    def do_strings(self):
        if self.voptions.basic.dostrings:
            try:
                data = open(self.memfile, "rb").read()
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening file %s" % e)

            nulltermonly = self.voptions.basic.get("strings_nullterminated_only", True)
            minchars = str(self.voptions.basic.get("strings_minchars", 5)).encode("utf-8")

            if nulltermonly:
                apat = b"([\x20-\x7e]{" + minchars + b",})\x00"
                upat = b"((?:[\x20-\x7e][\x00]){" + minchars + b",})\x00\x00"
            else:
                apat = b"[\x20-\x7e]{" + minchars + b",}"
                upat = b"(?:[\x20-\x7e][\x00]){" + minchars + b",}"

            strings = re.findall(apat, data)
            for ws in re.findall(upat, data):
                strings.append(ws.decode("utf-16le").encode("utf-8"))
            f = open(self.memfile + ".strings", "wb")
            f.write(b"\n".join(strings))
            f.close()
            return self.memfile + ".strings"
        return None

    def cleanup(self):
        """Delete the memory dump (if configured to do so)."""

        if self.voptions.basic.delete_memdump:
            for memfile in (self.memfile, self.memfile + ".zip"):
                try:
                    os.remove(memfile)
                except OSError:
                    log.error('Unable to delete memory dump file at path "%s" ', memfile)


class Memory(Processing):
    """Volatility Analyzer."""

    key = "memory"

    def run(self):
        """Run analysis.
        @return: volatility results dict.
        """
        self.voptions = Config("memory")

        results = {}
        if "machine" not in self.task or not self.task["machine"] or not self.task["memory"]:
            log.warn("Volatility startup: machine not in task list and no memory task specified.")
            return results

        task_machine = self.task["machine"]["name"]
        machine_manager = self.task["machine"]["manager"].lower()

        if HAVE_VOLATILITY:
            if self.memory_path and os.path.exists(self.memory_path):
                try:
                    vol = VolatilityManager(self.memory_path)
                    # only the memory dump and memory dump string paths are returned until vol3 is complete, strings output will be written if configured
                    # memory dump file will be handled as configured
                    results = vol.run(manager=machine_manager, vm=task_machine)
                except Exception:
                    log.exception("Generic error executing volatility")
                    if self.voptions.basic.delete_memdump_on_exception:
                        try:
                            os.remove(self.memory_path)
                        except OSError:
                            log.error('Unable to delete memory dump file at path "%s" ', self.memory_path)
            else:
                log.error("Memory dump not found: to run volatility you have to enable memory_dump")
        else:
            log.error("Cannot run volatility module: volatility library not available")

        return results
