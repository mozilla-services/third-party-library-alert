#!/usr/bin/env python

import os
import re
import sys
import requests
import traceback
import feedparser
from distutils.version import StrictVersion

ERROR = -1
OK = 0
UPDATE = 1


def get_mozilla_version(config):
	t = requests.get(config['current_version_file'])
	m = re.search(config['current_version_re'], t.text)
	if m:
		current_version = m.groups(0)[0]
		if config['verbose']:
			print "\tFound mozilla version", current_version
		return current_version 
	else:
		raise Exception("Could not match the regular expression '" + str(config['current_version_re']) + "' in the text\n\n" + str(t.text))


def get_latest_version(config):
	doc = feedparser.parse(config['repo_url'] + "releases.atom")

	if len(doc['entries']) < 1:
		raise Exception("No entries were found at the atom url")

	latest_version = doc['entries'][0]['link']

	#Clean up
	latest_version = latest_version.replace(config['repo_url'] + "releases/tag/", "")
	if latest_version[0] == 'v':
		latest_version = latest_version[1:]

	if config['verbose']:
		print "\tFound version", latest_version

	return latest_version

def check_version(config, current_version, latest_version):
	current_version = StrictVersion(current_version)
	latest_version = StrictVersion(latest_version)

	if latest_version < current_version:
		raise Exception("Latest version is older than current version")
	elif latest_version == current_version:
		if config['verbose']:
			print "\tUp to date"
		return OK
	else:
		if not config['verbose']:
			print "Examining", config['title'], "(" + config['location'] + ")" 
		print "\tCurrent version (" + str(current_version) + ") is behind latest (" + str(latest_version) + ")"
		return UPDATE


LIBRARIES = [
	{
		'title' : 'Harfbuzz',
		'location' : 'gfx/harfbuzz/',
		'repo_url' : 'https://github.com/behdad/harfbuzz/',
		'current_version_file': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/harfbuzz/README-mozilla",
		'current_version_re': "Current version:\s*([0-9\.]+)",
		'ignore' : '1.4.2' #1336500
	},
	{
		'title' : 'Graphite2',
		'location' : 'gfx/graphite',
		'repo_url': "https://github.com/silnrsi/graphite/",
		'current_version_file': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/graphite2/README.mozilla",
		'current_version_re': "This directory contains the Graphite2 library release ([0-9\.]+) from",
	},
	{
		'title' : 'Hunspell',
		'location' : 'extensions/spellcheck/hunspell/',
		'repo_url' : 'https://github.com/hunspell/hunspell/',
		'current_version_file': "https://hg.mozilla.org/mozilla-central/raw-file/tip/extensions/spellcheck/hunspell/src/README.mozilla",
		'current_version_re': "Hunspell Version:\s*v?([0-9\.]+)",
	},
]

if __name__ == "__main__":
	return_code = OK

	for l in LIBRARIES:
		config = l
		config['verbose'] = False

		if config['verbose']:
			print "Examining", config['title'], "(" + config['location'] + ")"

		try:
			current_version = get_mozilla_version(config)
			latest_version = get_latest_version(config)
			if 'ignore' in l and latest_version == l['ignore']:
				#We have an open bug for this already
				if config['verbose']:
					print"\tIgnoring outdated version, known bug"
				continue
			elif OK != check_version(config, current_version, latest_version):
				return_code = UPDATE
		except Exception as e:
			return_code = ERROR
			print "\tCaught an exception:"
			print traceback.format_exc()
	sys.exit(return_code)