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


################################################################################

def validate_config(config):
	if config['latest_version_fetch_type'] == 'github_rss' and \
	   not config['latest_version_fetch_location'].endswith('/'):
		config['latest_version_fetch_location'] += '/'

	if not config['current_version_fetch_location'].startswith('https://hg.mozilla.org/mozilla-central/raw-file/tip/'):
		raise Exception("current_version_fetch_location (" + config['current_version_fetch_location'] + ") does not appear to be a hg.mozilla link.")

	return config

################################################################################

def _current_version_hg_re(config):
	t = requests.get(config['current_version_fetch_location'])
	m = re.search(config['current_version_re'], t.text)
	if m:
		current_version = m.groups(0)[0]
		return current_version 
	else:
		raise Exception("Could not match the regular expression '" + str(config['current_version_re']) + "' in the text\n\n" + str(t.text))	

def get_mozilla_version(config):
	if config['current_version_fetch_type'] == 'hg.moz_re':
		current_version = _current_version_hg_re(config)
	else:
		raise Exception("Received an unknown current_version_fetch_type: " + str(config['current_version_fetch_type']))

	if config['verbose']:
		print "\tFound mozilla version", current_version

	return current_version
	

################################################################################

def _latest_version_github_rss(config):
	doc = feedparser.parse(config['latest_version_fetch_location'] + "releases.atom")

	if len(doc['entries']) < 1:
		raise Exception("No entries were found at the atom url")

	latest_version = doc['entries'][0]['link']

	#Clean up
	latest_version = latest_version.replace(config['latest_version_fetch_location'] + "releases/tag/", "")
	if latest_version[0] == 'v':
		latest_version = latest_version[1:]

	return latest_version

def _latest_version_html_re(config):
	flags = 0 if config['latest_version_fetch_type'] == 'singleline_html_re' else re.MULTILINE

	t = requests.get(config['latest_version_fetch_location'])
	m = re.search(config['latest_version_re'], t.text, flags)
	if m:
		latest_version = m.groups(0)[0]
		return latest_version 
	else:
		raise Exception("Could not match the regular expression '" + str(config['latest_version_re']) + "' in the text\n\n" + str(t.text))	
	return latest_version

def get_latest_version(config):
	if config['latest_version_fetch_type'] == 'github_rss':
		latest_version = _latest_version_github_rss(config)
	elif config['latest_version_fetch_type'] == 'multiline_html_re' or\
		 config['latest_version_fetch_type'] == 'singleline_html_re':
		latest_version = _latest_version_html_re(config)
	else:
		raise Exception("Received an unknown latest_version_fetch_type: " + str(config['latest_version_fetch_type']))

	if config['verbose']:
		print "\tFound version", latest_version

	return latest_version

################################################################################

def check_version(config, current_version, latest_version):
	if '.' not in current_version:
		current_version += '.0'
	if '.' not in latest_version:
		latest_version += '.0'
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
		'title' : 'sqlite',
		'location' : 'db/sqlite3',

		'latest_version_fetch_type' : 'multiline_html_re',
		'latest_version_fetch_location' : 'https://www.sqlite.org/chronology.html',
		'latest_version_re' : "<h1 align=center>History Of SQLite Releases<\/h1>\s+<center>\s+<table border=0 cellspacing=0>\s+<thead>\s+<tr><th>Date<th><th align='left'>Version\s+<\/thead>\s+<tbody>\s+<tr><td><a href='https:\/\/www\.sqlite\.org\/src\/timeline\?c=[0-9a-z]+\&y=ci'>[0-9-]+<\/a><\/td>\s+<td width='20'><\/td>\s+<td><a href=\"releaselog\/[0-9_]+\.html\">([0-9.]+)<\/a><\/td><\/tr>",

		'current_version_fetch_type' : 'hg.moz_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/old-configure.in",
		'current_version_re': "SQLITE_VERSION=([0-9\.]+)",
	},
	{
		'title' : 'pixman',
		'location' : 'gfx/cairo',

		'latest_version_fetch_type' : 'singleline_html_re',
		'latest_version_fetch_location' : 'https://www.cairographics.org/releases/',
		'latest_version_re' : "LATEST-pixman-([0-9.]+)",

		'current_version_fetch_type' : 'hg.moz_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/cairo/README",
		'current_version_re': "pixman \(([0-9\.]+)\)",
	},
	{
		'title' : 'skia',
		'location' : 'gfx/skia',

		'latest_version_fetch_type' : 'singleline_html_re',
		'latest_version_fetch_location' : 'https://skia.googlesource.com/skia/+/master/include/core/SkMilestone.h',
		'latest_version_re' : '<span class="pln"> SK_MILESTONE <\/span><span class="lit">([0-9]+)<\/span>',

		'current_version_fetch_type' : 'hg.moz_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/skia/skia/include/core/SkMilestone.h",
		'current_version_re': "SK_MILESTONE ([0-9]+)",
	},
	{
		'title' : 'Harfbuzz',
		'location' : 'gfx/harfbuzz/',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/behdad/harfbuzz/',

		'current_version_fetch_type' : 'hg.moz_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/harfbuzz/README-mozilla",
		'current_version_re': "Current version:\s*([0-9\.]+)",
		'ignore' : '1.4.2' #1336500
	},
	{
		'title' : 'Graphite2',
		'location' : 'gfx/graphite',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location': "https://github.com/silnrsi/graphite/",

		'current_version_fetch_type' : 'hg.moz_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/graphite2/README.mozilla",
		'current_version_re': "This directory contains the Graphite2 library release ([0-9\.]+) from",
	},
	{
		'title' : 'Hunspell',
		'location' : 'extensions/spellcheck/hunspell/',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/hunspell/hunspell/',

		'current_version_fetch_type' : 'hg.moz_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/extensions/spellcheck/hunspell/src/README.mozilla",
		'current_version_re': "Hunspell Version:\s*v?([0-9\.]+)",
	},
	{
		'title' : 'Codemirror',
		'location' : 'devtools/client/sourceeditor/codemirror/',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/codemirror/CodeMirror/',

		'current_version_fetch_type' : 'hg.moz_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/devtools/client/sourceeditor/codemirror/README",
		'current_version_re': "Currently used version is ([0-9\.]+)\. To upgrade",
	},
	{
		'title' : 'pdfjs',
		'location' : 'browser/extensions/pdfjs',
		'allows_ahead' : True,

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/mozilla/pdf.js',

		'current_version_fetch_type' : 'hg.moz_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/extensions/pdfjs/README.mozilla",
		'current_version_re': "Current extension version is: ([0-9\.]+)",
	},
	{
		'title' : 'ternjs',
		'location' : 'devtools/client/sourceeditor/tern',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/ternjs/tern',

		'current_version_fetch_type' : 'hg.moz_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/devtools/client/sourceeditor/tern/README",
		'current_version_re': "Currently used version is ([0-9\.]+)\.",
	},
	#{
	#	'title' : 'OTS',
	#	'location' : 'gfx/ots/',
	#	'repo_url' : 'https://github.com/khaledhosny/ots/',
	#	'current_version_fetch_location' : 'https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/ots/README.mozilla',
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

		config = validate_config(config)

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
					if 'allows_ahead' in config and config['allows_ahead']:
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