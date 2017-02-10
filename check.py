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
AHEAD = 2


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

################################################################################

def _latest_version_release_version(config):
	doc = feedparser.parse(config['repo_url'] + "releases.atom")

	if len(doc['entries']) < 1:
		raise Exception("No entries were found at the atom url")

	latest_version = doc['entries'][0]['link']

	#Clean up
	latest_version = latest_version.replace(config['repo_url'] + "releases/tag/", "")
	if latest_version[0] == 'v':
		latest_version = latest_version[1:]

	return latest_version

def _latest_version_git_commit(config):
	return latest_version

################################################################################

def get_latest_version(config):
	if not config['repo_url'].endswith('/'):
		config['repo_url'] += '/'

	if config['compare_type'] == 'release_version':
		latest_version = _latest_version_release_version(config)
	elif config['compare_type'] == 'git_commit':
		latest_version = _latest_version_git_commit(config)
	else:
		raise Exception("Received an unknown comparison type: " + str(config['compare_type']))

	if config['verbose']:
		print "\tFound version", latest_version

	return latest_version

################################################################################

def check_version(config, current_version, latest_version):
	current_version = StrictVersion(current_version)
	latest_version = StrictVersion(latest_version)

	if latest_version < current_version:
		return AHEAD
	elif latest_version == current_version:
		if config['verbose']:
			print "\tUp to date"
		return OK
	else:
		if not config['verbose']:
			print "Examining", config['title'], "(" + config['location'] + ")" 
		return UPDATE


################################################################################

LIBRARIES = [
	{
		'title' : 'Harfbuzz',
		'location' : 'gfx/harfbuzz/',
		'repo_url' : 'https://github.com/behdad/harfbuzz/',
		'compare_type' : 'release_version',
		'current_version_file': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/harfbuzz/README-mozilla",
		'current_version_re': "Current version:\s*([0-9\.]+)",
		'ignore' : '1.4.2' #1336500
	},
	{
		'title' : 'Graphite2',
		'location' : 'gfx/graphite',
		'compare_type' : 'release_version',
		'repo_url': "https://github.com/silnrsi/graphite/",
		'current_version_file': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/graphite2/README.mozilla",
		'current_version_re': "This directory contains the Graphite2 library release ([0-9\.]+) from",
	},
	{
		'title' : 'Hunspell',
		'location' : 'extensions/spellcheck/hunspell/',
		'compare_type' : 'release_version',
		'repo_url' : 'https://github.com/hunspell/hunspell/',
		'current_version_file': "https://hg.mozilla.org/mozilla-central/raw-file/tip/extensions/spellcheck/hunspell/src/README.mozilla",
		'current_version_re': "Hunspell Version:\s*v?([0-9\.]+)",
	},
	{
		'title' : 'Codemirror',
		'location' : 'devtools/client/sourceeditor/codemirror/',
		'compare_type' : 'release_version',
		'repo_url' : 'https://github.com/codemirror/CodeMirror/',
		'current_version_file': "https://dxr.mozilla.org/mozilla-central/source/devtools/client/sourceeditor/codemirror/README",
		'current_version_re': "Currently used version is ([0-9\.]+)\. To upgrade",
	},
	{
		'title' : 'pdfjs',
		'location' : 'browser/extensions/pdfjs',
		'compare_type' : 'release_version',
		'allows_ahead' : True,
		'repo_url' : 'https://github.com/mozilla/pdf.js',
		'current_version_file': "https://dxr.mozilla.org/mozilla-central/source/browser/extensions/pdfjs/README.mozilla",
		'current_version_re': "Current extension version is: ([0-9\.]+)",
	},
	#{
	#	'title' : 'OTS',
	#	'location' : 'gfx/ots/',
	#	'compare_type' : 'git_commit',
	#	'repo_url' : 'https://github.com/khaledhosny/ots/',
	#	'current_version_file' : 'https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/ots/README.mozilla',
	#	'current_version_re' : 'Current revision:\s*([0-9a-f]+)',
	#}
]

################################################################################

if __name__ == "__main__":
	verbose = False
	if '-v' in sys.argv:
		verbose = True

	return_code = OK

	for l in LIBRARIES:
		config = l
		config['verbose'] = verbose

		if config['verbose']:
			print "Examining", config['title'], "(" + config['location'] + ")"

		try:
			current_version = get_mozilla_version(config)
			latest_version = get_latest_version(config)
			status = check_version(config, current_version, latest_version)

			if status != OK:
				if 'ignore' in l and latest_version == l['ignore']:
					#We have an open bug for this already
					if config['verbose']:
						print"\tIgnoring outdated version, known bug"

				elif status == AHEAD:
					if config['allows_ahead']:
						if config['verbose']:
							print"\tIgnoring ahead version, config allows it"
					else:
						return_code = AHEAD # might be ovewritten by UPDATE or vice versa but doesn't matter
						print "\tCurrent version (" + str(current_version) + ") is AHEAD of latest (" + str(latest_version) + ")?!?!"


				else:
					print "\tCurrent version (" + str(current_version) + ") is behind latest (" + str(latest_version) + ")"
					return_code = UPDATE

		except Exception as e:
			return_code = ERROR
			print "\tCaught an exception:"
			print traceback.format_exc()
	sys.exit(return_code)