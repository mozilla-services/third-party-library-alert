#!/usr/bin/env python

# How to run locally in docker in a way that matches TaskCluster:
# docker run --rm ubuntu:14.04 bash -c "apt-get update && apt-get install -y python python-requests python-feedparser git && cd /tmp && git clone https://github.com/mozilla-services/third-party-library-alert.git && cd third-party-library-alert && ./check.py"

from __future__ import print_function

import os
import re
import sys
import json
import base64
import argparse
import datetime
import requests
import traceback
import feedparser
from distutils.version import LooseVersion

# Sometimes we don't do certificate validation because we're naughty
# Actually, the problem is that Ubuntu 14.04 (which is what TaskCluster uses)
# ships 2.7.6 which doesn't give us SNI support.
# See http://docs.python-requests.org/en/master/community/faq/#what-are-hostname-doesn-t-match-errors
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass


ERROR = -1
OK = 0
UPDATE = 1
AHEAD = 2


################################################################################


def validate_config(config):
    if "library_ignored" not in config:
        config["library_ignored"] = False
    else:
        # If we're ignoring this library, we don't need the other checks
        return config

    if config["latest_version_fetch_type"] == "github_rss" and not config[
        "latest_version_fetch_location"
    ].endswith("/"):
        config["latest_version_fetch_location"] += "/"

    if (
        "current_version_fetch_location" in config
        and config["current_version_fetch_location"].startswith(
            "https://hg.mozilla.org/"
        )
        and not config["current_version_fetch_location"].startswith(
            "https://hg.mozilla.org/mozilla-central/raw-file/tip/"
        )
    ):
        raise Exception(
            "current_version_fetch_location ("
            + config["current_version_fetch_location"]
            + ") does not appear to be a raw hg.mozilla link."
        )

    if "filing_info" not in config:
        config["filing_info"] = ""
    if "most_recent_bug" not in config:
        config["most_recent_bug"] = ""

    if "current_version_fetch_ssl_verify" not in config:
        config["current_version_fetch_ssl_verify"] = True
    if "latest_version_fetch_ssl_verify" not in config:
        config["latest_version_fetch_ssl_verify"] = True

    if "compare_type" not in config:
        config["compare_type"] = "version"

    if "print_additional_library_info" not in config:
        config["print_additional_library_info"] = ""

    for i in [
        "current_version_post_alter",
        "latest_version_post_alter",
        "print_latest_version_fetch_location_munge",
    ]:
        if i in config:
            config[i] = eval(config[i])

    return config


def munge_config_for_printing(config):
    if "print_latest_version_fetch_location_munge" in config:
        config["latest_version_fetch_location"] = config[
            "print_latest_version_fetch_location_munge"
        ](config["latest_version_fetch_location"])

    return config


################################################################################


def _fetch_html_re(fetch_type, fetch_location, fetch_ssl_verify, regular_expression):
    flags = re.DOTALL if fetch_type == "dotall_html_re" else 0

    t = requests.get(fetch_location, verify=fetch_ssl_verify)
    if fetch_type == "html_re_base64":
        searchtext = base64.b64decode(t.text)
    else:
        searchtext = t.text

    m = re.search(regular_expression, searchtext, flags)
    if m:
        matched_text = m.groups(0)[0]
        return matched_text
    else:
        raise Exception(
            u"Could not match the regular expression '"
            + regular_expression
            + u"' in the text at "
            + fetch_location
            + "\n\n"
        )


################################################################################


def get_mozilla_version(config):
    if "html_re" in config["current_version_fetch_type"]:
        current_version = _fetch_html_re(
            config["current_version_fetch_type"],
            config["current_version_fetch_location"],
            config["current_version_fetch_ssl_verify"],
            config["current_version_re"],
        )
    elif config["current_version_fetch_type"] == "hardcoded":
        current_version = config["current_version_fetch_location"]
    elif config["current_version_fetch_type"] == "list":
        raise Exception("List not implemented for Mozilla")
    else:
        raise Exception(
            "Received an unknown current_version_fetch_type: "
            + str(config["current_version_fetch_type"])
        )

    if "current_version_post_alter" in config:
        current_version = config["current_version_post_alter"](current_version)

    if config["verbose"]:
        print("\tFound mozilla version", current_version)

    return current_version


################################################################################


def _latest_version_github_rss(config):
    doc = feedparser.parse(config["latest_version_fetch_location"] + "releases.atom")

    if len(doc["entries"]) < 1:
        raise Exception("No entries were found at the atom url")

    latest_version = doc["entries"][0]["link"]

    # Clean up
    latest_version = latest_version.replace(
        config["latest_version_fetch_location"] + "releases/tag/", ""
    )
    if latest_version[0] == "v":
        latest_version = latest_version[1:]

    return latest_version


def _latest_version_directory_crawl(config):
    t = requests.get(
        config["latest_version_fetch_location"],
        verify=config["latest_version_fetch_ssl_verify"],
    )
    regex = (
        '<a href="'
        + config["latest_version_file_prefix_re"]
        + "([0-9.]+)"
        + config["latest_version_file_suffix_re"]
    )
    m = re.findall(regex, t.text)

    if m:
        max_ver = None
        for i in m:
            this_ver = LooseVersion(i)
            if not max_ver:
                max_ver = this_ver
            elif this_ver > max_ver:
                max_ver = this_ver
        return str(max_ver)
    else:
        raise Exception(
            "Could not match the regular expression '"
            + str(regex)
            + "' in the text\n\n"
            + str(t.text)
        )


def _latest_version_list(config):
    # Find all files with a commit newer than the current version date, but put the 'latest' version as the most recent
    min_value = datetime.datetime.strptime("2000-01-01T12:00:00Z", "%Y-%m-%dT%H:%M:%SZ")
    newest_latest_version = min_value

    for i in config["latest_version_fetch_location_list"]:
        this_latest_version = _fetch_html_re(
            "html_re",
            config["latest_version_fetch_location_base"] + i,
            config["latest_version_fetch_ssl_verify"],
            config["latest_version_re"],
        )
        this_latest_version_date = datetime.datetime.strptime(
            this_latest_version, config["latest_version_date_format_string"]
        )

        fake_config = {
            "current_version": config["current_version"],
            "current_version_date_format_string": config[
                "current_version_date_format_string"
            ],
            "latest_version": this_latest_version,
            "latest_version_date_format_string": config[
                "latest_version_date_format_string"
            ],
            "compare_date_lag": 0,
            "verbose": False,
        }
        if newest_latest_version == min_value:
            newest_latest_version = this_latest_version
            config["latest_version_fetch_location"] = (
                config["latest_version_fetch_location_base"] + i
            )
        elif (
            datetime.datetime.strptime(
                newest_latest_version, config["latest_version_date_format_string"]
            )
            < this_latest_version_date
        ):
            newest_latest_version = this_latest_version
            config["latest_version_fetch_location"] = (
                config["latest_version_fetch_location_base"] + i
            )

        if _compare_type_date(fake_config) == UPDATE:
            if "latest_version_addition_info_re" in config:
                if "print_additional_library_info" not in config:
                    config["print_additional_library_info"] = ""
                config["print_additional_library_info"] += (
                    "\n-----------------------\nMost Recent Commit Message for "
                    + i
                    + ":\n"
                    + _fetch_html_re(
                        "html_re",
                        config["latest_version_fetch_location_base"] + i,
                        config["latest_version_fetch_ssl_verify"],
                        config["latest_version_addition_info_re"],
                    )
                )
    return newest_latest_version


def get_latest_version(config):
    if config["latest_version_fetch_type"] == "github_rss":
        latest_version = _latest_version_github_rss(config)
    elif config["latest_version_fetch_type"] == "github_hash":
        latest_version = _fetch_html_re(
            "html_re",
            config["latest_version_fetch_location"] + "/commits/master",
            True,
            '([a-fA-F0-9]{40})" class="d-none js-permalink-shortcut" data-hotkey="y">Permalink</a>',
        )
    elif config["latest_version_fetch_type"] == "hardcoded":
        latest_version = config["latest_version_fetch_location"]
    elif config["latest_version_fetch_type"] == "list":
        if config["compare_type"] != "date":
            raise Exception("Lsit type is only supported with Date Comparison")
        latest_version = _latest_version_list(config)
    elif config["latest_version_fetch_type"] == "find_in_directory":
        latest_version = _latest_version_directory_crawl(config)
    elif "html_re" in config["latest_version_fetch_type"]:
        latest_version = _fetch_html_re(
            config["latest_version_fetch_type"],
            config["latest_version_fetch_location"],
            config["latest_version_fetch_ssl_verify"],
            config["latest_version_re"],
        )
    else:
        raise Exception(
            "Received an unknown latest_version_fetch_type: "
            + str(config["latest_version_fetch_type"])
        )

    if "latest_version_post_alter" in config:
        latest_version = config["latest_version_post_alter"](latest_version)

    if config["verbose"]:
        print("\tFound version", latest_version)

    return latest_version


################################################################################
def _compare_type_version(config):
    if "." not in config["current_version"]:
        current_version = config["current_version"] + ".0"
    if "." not in config["latest_version"]:
        latest_version = config["latest_version"] + ".0"
    current_version = LooseVersion(config["current_version"])
    latest_version = LooseVersion(config["latest_version"])

    if latest_version < current_version:
        return AHEAD
    elif latest_version == current_version:
        if config["verbose"]:
            print("\tUp to date")
        return OK
    else:
        return UPDATE


def _compare_type_equality(config):
    if config["latest_version"] != config["current_version"]:
        return UPDATE
    elif config["latest_version"] == config["current_version"]:
        if config["verbose"]:
            print("\tUp to date")
        return OK
    else:
        raise Exception("Uh....?")


def _compare_type_date(config):
    config["current_version"] = datetime.datetime.strptime(
        config["current_version"], config["current_version_date_format_string"]
    )
    config["latest_version"] = datetime.datetime.strptime(
        config["latest_version"], config["latest_version_date_format_string"]
    )

    td = config["latest_version"] - config["current_version"]
    td = (
        td + -2 * td if td < datetime.timedelta() else td
    )  # Handle negatives (we kind of ignore timezones...)
    if td >= datetime.timedelta(days=config["compare_date_lag"]):
        status = UPDATE
    else:
        if config["latest_version"] != config["current_version"] and config["verbose"]:
            print(
                "\tIgnoring a new commit that is not more than",
                config["compare_date_lag"],
                "days old",
            )
        status = OK
    return status


################################################################################
def read_json_file():
    f = open("libraries.json")
    lines = f.readlines()
    almost_json = []
    for l in lines:
        if not l.strip().startswith("#"):
            almost_json.append(l)

    almost_json = "".join(almost_json)
    try:
        LIBRARIES = json.loads(almost_json)
    except:
        print("Error decoding json:")
        print(almost_json)
    return LIBRARIES


def fetch_and_compare(config):
    config["current_version"] = get_mozilla_version(config)
    config["latest_version"] = get_latest_version(config)

    should_ignore = False
    if config["compare_type"] == "version":
        status = _compare_type_version(config)
        if (
            status != OK
            and "ignore" in config
            and config["latest_version"] == config["ignore"]
        ):
            if "ignore_until" in config:
                ignore_until = datetime.datetime.strptime(
                    config["ignore_until"], config["ignore_date_format_string"]
                )
                if datetime.datetime.now() < ignore_until:
                    should_ignore = True
            else:
                should_ignore = True

    elif config["compare_type"] == "equality":
        status = _compare_type_equality(config)
        if (
            status != OK
            and "ignore" in config
            and config["latest_version"] == config["ignore"]
        ):
            if "ignore_until" in config:
                ignore_until = datetime.datetime.strptime(
                    config["ignore_until"], config["ignore_date_format_string"]
                )
                if datetime.datetime.now() < ignore_until:
                    should_ignore = True
            else:
                should_ignore = True

    elif config["compare_type"] == "date":
        status = _compare_type_date(config)
        if status == UPDATE and "ignore" in config:
            ignore_date = datetime.datetime.strptime(
                config["ignore"], config["ignore_date_format_string"]
            )
            if config["latest_version"] - ignore_date <= datetime.timedelta(
                days=config["compare_date_lag"]
            ):
                if "ignore_until" in config:
                    ignore_until = datetime.datetime.strptime(
                        config["ignore_until"], config["ignore_date_format_string"]
                    )
                    if datetime.datetime.now() < ignore_until:
                        should_ignore = True
                else:
                    should_ignore = True

    else:
        raise Exception("Unknown comparison type: " + str(config["compare_type"]))

    if status != OK:
        if should_ignore:
            status = OK
            # We have an open bug for this already
            if config["verbose"]:
                print("\tIgnoring outdated version, known bug")

        elif status == AHEAD:
            if "allows_ahead" in config and config["allows_ahead"]:
                status = OK
                if config["verbose"]:
                    print("\tIgnoring ahead version, config allows it")
            else:
                if config["verbose"]:
                    print(
                        "\tCurrent version ("
                        + str(config["current_version"])
                        + ") is AHEAD of latest ("
                        + str(config["latest_version"])
                        + ")?!?!"
                    )

                config = munge_config_for_printing(config)
                print(bug_message % config)

        else:
            if config["verbose"]:
                print(
                    "\tCurrent version ("
                    + str(config["current_version"])
                    + ") is behind latest ("
                    + str(config["latest_version"])
                    + ")"
                )

            config = munge_config_for_printing(config)
            print(bug_message % config)

    config["status"] = status

    return config


################################################################################

bug_message = """
=========================
Update %(title)s to %(latest_version)s
---------
Whiteboard: [third-party-lib-audit] %(filing_info)s 
Most Recent: %(most_recent_bug)s
---------
This is a (semi-)automated bug making you aware that there is an available upgrade for an embedded third-party library. You can leave this bug open, and it will be updated if a newer version of the library becomes available. If you close it as WONTFIX, please indicate if you do not wish to receive any future bugs upon new releases of the library.

%(title)s is currently at version %(current_version)s in mozilla-central, and the latest version of the library released is %(latest_version)s. 

I fetched the latest version of the library from %(latest_version_fetch_location)s.

%(print_additional_library_info)s
=========================
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan Firefox source code for out of date third party libraries."
    )
    parser.add_argument("-v", action="store_true", required=False, help="Verbose")
    parser.add_argument(
        "--list",
        action="store_true",
        required=False,
        help="Check the script's database against ThirdPartyPaths.txt",
    )
    parser.add_argument(
        "libraries",
        nargs="*",
        metavar="[libraries]",
        type=str,
        help='Libraries to scan (blank for "all"',
    )
    args = parser.parse_args()

    return_code = OK

    LIBRARIES = read_json_file()

    if args.list:
        # Set subtraction on the libraries I know about
        allThirdPartyLibraries = set(
            requests.get(
                "https://hg.mozilla.org/mozilla-central/raw-file/tip/tools/rewriting/ThirdPartyPaths.txt"
            ).text.split("\n")
        )
        knownThirdPartyLibraries = set([l["location"] for l in LIBRARIES])
        missingThirdPartyLibraries = allThirdPartyLibraries - knownThirdPartyLibraries

        # Also find and then subtract out any library whose path is a part of/a/path/like/this/*
        libraryPaths = [
            l["location"][:-1] for l in LIBRARIES if l["location"].endswith("*")
        ]
        subtractAdditional = set()
        for m in missingThirdPartyLibraries:
            for l in libraryPaths:
                if m.startswith(l):
                    subtractAdditional.add(m)
        missingThirdPartyLibraries = missingThirdPartyLibraries - subtractAdditional

        # Okay, now print.
        if not missingThirdPartyLibraries:
            print("No Libraries missing!")
        for m in sorted(missingThirdPartyLibraries):
            print(m)
        sys.exit(0)

        # Normal operation
    for l in LIBRARIES:
        if args.libraries and l["title"] not in args.libraries:
            continue

        config = l
        config["verbose"] = args.v or args.libraries

        config = validate_config(config)

        if l["library_ignored"]:
            continue

        if config["verbose"]:
            print("Examining", config["title"], "(" + config["location"] + ")")

        try:
            result = fetch_and_compare(config)

            if result["status"] != OK:
                return_code = result["status"]

        except Exception as e:
            return_code = ERROR
            print("\tCaught an exception processing", config["title"])
            print(traceback.format_exc())

    sys.exit(return_code)
