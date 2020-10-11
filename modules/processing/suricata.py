# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
import shutil
import subprocess
import time
from datetime import datetime

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import convert_to_printable

log = logging.getLogger(__name__)


# TODO: cleanup and test Suricata module
class Suricata(Processing):
    """Suricata processing."""

    key = "suricata"

    # Add to this if you wish to ignore any SIDs for the suricata alert logs
    # Useful for ignoring SIDs without disabling them. Ex: surpress an alert for
    # a SID which is a dependent of another. (Bad TCP data for HTTP(S) alert)
    sid_blacklist = {
        2200074,  # SURICATA FRAG IPv6 Fragmentation overlap
        2017363,  # ET INFO InetSim Response from External Source Possible SinkHole
        2200075,  # SURICATA UDPv4 invalid checksum
        2019416,  # ET POLICY SSLv3 outbound connection from client vulnerable to POODLE attack
    }

    def cmd_wrapper(self, cmd, **kwargs):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
        stdout, stderr = p.communicate()
        return p.returncode, stdout, stderr

    def sort_by_timestamp(self, unsorted):
        # Convert time string into a datetime object for sorting
        for item in unsorted:
            oldtime = item["timestamp"]
            newtime = datetime.strptime(oldtime[:-5], "%Y-%m-%d %H:%M:%S.%f")
            item["timestamp"] = newtime

        tmp = sorted(unsorted, key=lambda k: k["timestamp"])
        # Iterate sorted, converting datetime object back to string for display later
        for item in tmp:
            item["timestamp"] = datetime.strftime(item["timestamp"], "%Y-%m-%d %H:%M:%S.%f")[:-3]

        return tmp

    def run(self):
        """Run Suricata.
        @return: hash with alerts
        """

        # General
        SURICATA_CONF = self.options.conf or ""
        SURICATA_EVE_LOG_FULL_PATH = os.path.join(self.logs_path, self.options.evelog or "")
        SURICATA_ALERT_LOG_FULL_PATH = os.path.join(self.logs_path, self.options.alertlog or "")
        SURICATA_TLS_LOG_FULL_PATH = os.path.join(self.logs_path, self.options.tlslog or "")
        SURICATA_HTTP_LOG_FULL_PATH = os.path.join(self.logs_path, self.options.httplog or "")
        SURICATA_SSH_LOG_FULL_PATH = os.path.join(self.logs_path, self.options.sshlog or "")
        SURICATA_DNS_LOG_FULL_PATH = os.path.join(self.logs_path, self.options.dnslog or "")
        SURICATA_FILE_LOG_FULL_PATH = os.path.join(self.logs_path, self.options.fileslog or "")
        SURICATA_FILES_DIR_FULL_PATH = os.path.join(self.logs_path, self.options.filesdir or "")
        SURICATA_RUNMODE = self.options.runmode or ""
        SURICATA_FILE_BUFFER = self.options.buffer or 8192
        Z7_PATH = self.options.get("7zbin") or ""
        FILES_ZIP_PASS = self.options.zippass or ""

        # Socket
        SURICATA_SOCKET_PATH = self.options.socket_file or ""

        # Command line
        SURICATA_BIN = self.options.bin or ""

        suricata = {
            "alerts": [],
            "tls": [],
            "perf": [],
            "files": [],
            "http": [],
            "dns": [],
            "ssh": [],
            "fileinfo": [],
            "eve_log_full_path": None,
            "alert_log_full_path": None,
            "tls_log_full_path": None,
            "http_log_full_path": None,
            "file_log_full_path": None,
            "ssh_log_full_path": None,
            "dns_log_full_path": None,
        }

        tls_items = ("fingerprint", "issuer", "version", "subject", "sni", "ja3", "serial")

        separate_log_paths = (
            ("alert_log_full_path", SURICATA_ALERT_LOG_FULL_PATH),
            ("tls_log_full_path", SURICATA_TLS_LOG_FULL_PATH),
            ("http_log_full_path", SURICATA_HTTP_LOG_FULL_PATH),
            ("ssh_log_full_path", SURICATA_SSH_LOG_FULL_PATH),
            ("dns_log_full_path", SURICATA_DNS_LOG_FULL_PATH),
        )

        # handle reprocessing
        all_log_paths = [x[1] for x in separate_log_paths] + [SURICATA_EVE_LOG_FULL_PATH, SURICATA_FILE_LOG_FULL_PATH]
        for log_path in all_log_paths:
            if not os.path.exists(log_path):
                continue
            try:
                os.unlink(log_path)
            except OSError:
                pass

        if os.path.isdir(SURICATA_FILES_DIR_FULL_PATH):
            try:
                shutil.rmtree(SURICATA_FILES_DIR_FULL_PATH, ignore_errors=True)
            except OSError:
                pass

        if not os.path.exists(SURICATA_CONF):
            log.warning("Unable to run Suricata: Conf file %r does not exist", SURICATA_CONF)
            return suricata

        if not os.path.exists(self.pcap_path):
            log.warning("Unable to run Suricata: Pcap file %r does not exist", self.pcap_path)
            return suricata

        if SURICATA_RUNMODE == "socket":
            try:
                # from suricatasc import SuricataSC
                from lib.cuckoo.common.suricatasc import SuricataSC
            except Exception as e:
                log.warning("Failed to import suricatasc lib: %s", e)
                return suricata

            loopcnt = 0
            maxloops = 24
            loopsleep = 5

            args = {
                "filename": self.pcap_path,
                "output-dir": self.logs_path,
            }

            suris = SuricataSC(SURICATA_SOCKET_PATH)
            try:
                suris.connect()
                suris.send_command("pcap-file", args)
            except Exception as e:
                log.warning("Failed to connect to socket and send command %s: %s", SURICATA_SOCKET_PATH, e)
                return suricata

            while loopcnt < maxloops:
                try:
                    pcap_flist = suris.send_command("pcap-file-list")
                    current_pcap = suris.send_command("pcap-current")
                    log.debug("pcapfile list: %s current pcap: %s", pcap_flist, current_pcap)

                    if self.pcap_path not in pcap_flist["message"]["files"] and current_pcap["message"] != self.pcap_path:
                        log.debug("Pcap not in list and not current pcap lets assume it's processed")
                        break
                    else:
                        loopcnt = loopcnt + 1
                        time.sleep(loopsleep)
                except Exception as e:
                    log.warning("Failed to get pcap status breaking out of loop: %s", e)
                    break

            if loopcnt == maxloops:
                log.warning("Loop timeout of %d sec occurred waiting for file %s to finish processing", maxloops * loopsleep, current_pcap)
                return suricata

        elif SURICATA_RUNMODE == "cli":
            if not os.path.exists(SURICATA_BIN):
                log.warning("Unable to run Suricata: Bin file %s does not exist", SURICATA_CONF)
                return suricata["alerts"]

            ret, _, stderr = self.cmd_wrapper([SURICATA_BIN, "-c", SURICATA_CONF, "-k", "none", "-l", self.logs_path, "-r", self.pcap_path])
            if ret != 0:
                log.warning("Suricata returned an exit value other than zero: %s", stderr)
                return suricata

        else:
            log.warning("Unknown Suricata runmode")
            return suricata

        datalist = []
        if os.path.exists(SURICATA_EVE_LOG_FULL_PATH):
            suricata["eve_log_full_path"] = SURICATA_EVE_LOG_FULL_PATH
            with open(SURICATA_EVE_LOG_FULL_PATH, "rt") as f:
                datalist.append(f.read())
        else:
            for path in separate_log_paths:
                if os.path.exists(path[1]):
                    suricata[path[0]] = path[1]
                    with open(path[1], "rt") as f:
                        datalist.append(f.read())

        if not datalist:
            log.warning("Suricata: Failed to find usable Suricata log file")

        parsed_files = []
        for data in datalist:
            for line in data.splitlines():
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("Suricata: Failed to parse line %r as json", line)
                    continue

                event_type = parsed.get("event_type")
                if event_type == "alert":
                    alert = parsed.get("alert") or {}
                    if parsed["alert"]["signature_id"] not in self.sid_blacklist and not parsed["alert"]["signature"].startswith("SURICATA STREAM"):
                        alog = {
                            "gid": alert.get("gid") or "None",
                            "rev": alert.get("rev") or "None",
                            "severity": alert.get("severity") or "None",
                            "sid": alert["signature_id"],
                            "srcport": parsed.get("src_port", "None"),
                            "srcip": parsed["src_ip"],
                            "dstport": parsed.get("dest_port", "None"),
                            "dstip": parsed["dest_ip"],
                            "protocol": parsed["proto"],
                            "timestamp": parsed["timestamp"].replace("T", " "),
                            "category": alert.get("category") or "None",
                            "signature": alert["signature"],
                        }
                        suricata["alerts"].append(alog)

                elif event_type == "http":
                    hlog = {
                        "srcport": parsed["src_port"],
                        "srcip": parsed["src_ip"],
                        "dstport": parsed["dest_port"],
                        "dstip": parsed["dest_ip"],
                        "timestamp": parsed["timestamp"].replace("T", " "),
                    }
                    for k, v in {
                        "uri": "url",
                        "length": "length",
                        "hostname": "hostname",
                        "status": "status",
                        "http_method": "http_method",
                        "contenttype": "http_content_type",
                        "ua": "http_user_agent",
                        "referrer": "http_refer",
                    }.items():
                        hlog[k] = parsed.get("http", {}).get(v, "None")
                    suricata["http"].append(hlog)

                elif event_type == "tls":
                    tlog = {
                        "srcport": parsed["src_port"],
                        "srcip": parsed["src_ip"],
                        "dstport": parsed["dest_port"],
                        "dstip": parsed["dest_ip"],
                        "timestamp": parsed["timestamp"].replace("T", " "),
                    }
                    for key in tls_items:
                        if key in parsed["tls"]:
                            tlog[key] = parsed["tls"][key]
                    suricata["tls"].append(tlog)

                elif event_type == "ssh":
                    suricata["ssh"].append(parsed)
                elif event_type == "dns":
                    suricata["dns"].append(parsed)
                elif event_type == "fileinfo":
                    flog = {
                        "http_host": parsed.get("http", {}).get("hostname", ""),
                        "http_uri": parsed.get("http", {}).get("url", ""),
                        "http_referer": parsed.get("http", {}).get("referer", ""),
                        "http_user_agent": parsed.get("http", {}).get("http_user_agent", ""),
                        "protocol": parsed.get("proto", ""),
                        "magic": parsed.get("fileinfo", {}).get("magic", ""),
                        "size": parsed.get("fileinfo", {}).get("size", ""),
                        "stored": parsed.get("fileinfo", {}).get("stored", ""),
                        "sha256": parsed.get("fileinfo", {}).get("sha256", ""),
                        "md5": parsed.get("fileinfo", {}).get("md5", ""),
                        "filename": parsed.get("fileinfo", {}).get("filename", ""),
                        "file_info": {},
                    }
                    if "/" in flog["filename"]:
                        flog["filename"] = flog["filename"].split("/")[-1]
                    parsed_files.append(flog)

        if parsed_files:
            for sfile in parsed_files:
                if sfile.get("stored", False):
                    filename = sfile["sha256"]
                    src_file = os.path.join(SURICATA_FILES_DIR_FULL_PATH, filename[0:2], filename)
                    dst_file = os.path.join(SURICATA_FILES_DIR_FULL_PATH, filename)
                    if os.path.exists(src_file):
                        try:
                            shutil.move(src_file, dst_file)
                        except OSError as e:
                            log.warning("Unable to move Suricata file: %s", e)
                            break
                        file_info = File(file_path=dst_file).get_all()
                        try:
                            with open(file_info["path"], "r") as drop_open:
                                filedata = drop_open.read(SURICATA_FILE_BUFFER + 1)
                            if len(filedata) > SURICATA_FILE_BUFFER:
                                filedata = filedata[:SURICATA_FILE_BUFFER] + " <truncated>"
                            file_info["data"] = convert_to_printable(filedata)
                        except UnicodeDecodeError as e:
                            pass
                        if file_info:
                            sfile["file_info"] = file_info
                    suricata["files"].append(sfile)
            with open(SURICATA_FILE_LOG_FULL_PATH, "w") as drop_log:
                drop_log.write(json.dumps(suricata["files"], indent=4))

            # Cleanup file subdirectories left behind by messy Suricata
            for dirpath, dirnames, filenames in os.walk(SURICATA_FILES_DIR_FULL_PATH):
                if dirnames or filenames:
                    continue
                try:
                    shutil.rmtree(dirpath)
                except OSError as e:
                    log.warning("Unable to delete Suricata file subdirectories: %s", e)

        if SURICATA_FILES_DIR_FULL_PATH and os.path.exists(SURICATA_FILES_DIR_FULL_PATH) and Z7_PATH and os.path.exists(Z7_PATH):
            ret, _, _ = self.cmd_wrapper([Z7_PATH, "a", "-p" + FILES_ZIP_PASS, "-y", "files.zip", SURICATA_FILE_LOG, SURICATA_FILES_DIR], cwd=self.logs_path)
            if ret > 1:
                log.warning("Suricata: Failed to create %s - Error %s", os.path.join(self.logs_path, "files.zip"), ret)

        suricata["alerts"] = self.sort_by_timestamp(suricata["alerts"])
        suricata["http"] = self.sort_by_timestamp(suricata["http"])
        suricata["tls"] = self.sort_by_timestamp(suricata["tls"])

        return suricata
