#!/usr/bin/env python

import os
import re
import sys
import datetime
import requests
import traceback
import feedparser
from distutils.version import LooseVersion

# Sometimes we don't do certificate validation because we're naughty
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
	if config['latest_version_fetch_type'] == 'github_rss' and \
	   not config['latest_version_fetch_location'].endswith('/'):
		config['latest_version_fetch_location'] += '/'

	if config['current_version_fetch_location'].startswith('https://hg.mozilla.org/') \
		and not config['current_version_fetch_location'].startswith('https://hg.mozilla.org/mozilla-central/raw-file/tip/'):
		raise Exception("current_version_fetch_location (" + config['current_version_fetch_location'] + ") does not appear to be a raw hg.mozilla link.")

	if 'filing_info' not in config:
		config['filing_info'] = ''

	if 'current_version_fetch_ssl_verify' not in config:
		config['current_version_fetch_ssl_verify'] = True
	if 'latest_version_fetch_ssl_verify' not in config:
		config['latest_version_fetch_ssl_verify'] = True

	if 'compare_type' not in config:
		config['compare_type'] = 'version'

	return config

################################################################################

def _fetch_html_re(fetch_type, fetch_location, fetch_ssl_verify, regular_expression):
	flags = re.DOTALL if fetch_type == 'dotall_html_re' else 0

	t = requests.get(fetch_location, verify=fetch_ssl_verify)
	m = re.search(regular_expression, t.text, flags)
	if m:
		matched_text = m.groups(0)[0]
		return matched_text 
	else:
		raise Exception(u"Could not match the regular expression '" + regular_expression + u"' in the text\n\n" + t.text)

################################################################################

def get_mozilla_version(config):
	if config['current_version_fetch_type'] == 'html_re':
		current_version = _fetch_html_re(config['current_version_fetch_type'], 
			config['current_version_fetch_location'],
			config['current_version_fetch_ssl_verify'], 
			config['current_version_re'])
	elif config['current_version_fetch_type'] == 'hardcoded':
		current_version = config['current_version_fetch_location']
	else:
		raise Exception("Received an unknown current_version_fetch_type: " + str(config['current_version_fetch_type']))

	if 'current_version_post_alter' in config:
		current_version = config['current_version_post_alter'](current_version)

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

def _latest_version_directory_crawl(config):
	t = requests.get(config['latest_version_fetch_location'], verify=config['latest_version_fetch_ssl_verify'])
	regex = '<a href="' + config['latest_version_file_prefix_re'] + '([0-9.]+)' + config['latest_version_file_suffix_re']
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
		raise Exception("Could not match the regular expression '" + str(regex) + "' in the text\n\n" + str(t.text))	

def get_latest_version(config):
	if config['latest_version_fetch_type'] == 'github_rss':
		latest_version = _latest_version_github_rss(config)
	elif config['latest_version_fetch_type'] == 'find_in_directory':
		latest_version = _latest_version_directory_crawl(config)
	elif 'html_re' in config['latest_version_fetch_type']:
		latest_version = _fetch_html_re(config['latest_version_fetch_type'], 
			config['latest_version_fetch_location'],
			config['latest_version_fetch_ssl_verify'], 
			config['latest_version_re'])
	else:
		raise Exception("Received an unknown latest_version_fetch_type: " + str(config['latest_version_fetch_type']))

	if 'latest_version_post_alter' in config:
		latest_version = config['latest_version_post_alter'](latest_version)

	if config['verbose']:
		print "\tFound version", latest_version

	return latest_version

################################################################################
def _compare_type_version(config):
	if '.' not in config['current_version']:
		current_version = config['current_version'] + '.0'
	if '.' not in config['latest_version']:
		latest_version = config['latest_version'] + '.0'
	current_version = LooseVersion(config['current_version'])
	latest_version = LooseVersion(config['latest_version'])

	if latest_version < current_version:
		return AHEAD
	elif latest_version == current_version:
		if config['verbose']:
			print "\tUp to date"
		return OK
	else:
		return UPDATE

def _compare_type_equality(config):
	if config['latest_version'] != config['current_version']:
		return UPDATE
	elif config['latest_version'] == config['current_version']:
		if config['verbose']:
			print "\tUp to date"
		return OK
	else:
		raise Exception("Uh....?")

def _compare_type_date(config):
	config['current_version'] = datetime.datetime.strptime(config['current_version'], config['current_version_date_format_string'])
	config['latest_version'] = datetime.datetime.strptime(config['latest_version'], config['latest_version_date_format_string'])

	if config['latest_version'] - config['current_version'] > datetime.timedelta(days=config['compare_date_lag']):
		status = UPDATE
	else:
		if config['latest_version'] != config['current_version'] and config['verbose']:
			print"\tIgnoring a new commit that is not more than", config['compare_date_lag'], "days old"
		status = OK
	return status

################################################################################
def fetch_and_compare(config):
	config['current_version'] = get_mozilla_version(config)
	config['latest_version'] = get_latest_version(config)
	
	should_ignore = False
	if config['compare_type'] == 'version':
		status = _compare_type_version(config)
		if status != OK and 'ignore' in config and config['latest_version'] == config['ignore']:
			should_ignore = True

	elif config['compare_type'] == 'equality':
		status = _compare_type_equality(config)
		if status != OK and 'ignore' in config and config['latest_version'] == config['ignore']:
			should_ignore = True

	elif config['compare_type'] == 'date':
		status = _compare_type_date(config)

		if status == UPDATE and 'ignore' in config:
			ignore_date = datetime.datetime.strptime(config['ignore'], config['ignore_date_format_string'])
			if config['latest_version'] - ignore_date < datetime.timedelta(days=config['compare_date_lag']):
				should_ignore = True

	if status != OK:
		if should_ignore:
			status = OK
			#We have an open bug for this already
			if config['verbose']:
				print"\tIgnoring outdated version, known bug"

		elif status == AHEAD:
			if 'allows_ahead' in config and config['allows_ahead']:
				status = OK
				if config['verbose']:
					print"\tIgnoring ahead version, config allows it"
			else:
				if config['verbose']:
					print "\tCurrent version (" + str(config['current_version']) + ") is AHEAD of latest (" + str(config['latest_version']) + ")?!?!"
		
		else:
			if config['verbose']:
				print "\tCurrent version (" + str(config['current_version']) + ") is behind latest (" + str(config['latest_version']) + ")"

			print bug_message % config
	
	config['status'] = status

	return config

################################################################################

#ryanvm:
#libevent

#libpng can be ignored since the maintainer updates it

LIBRARIES = [
	{
		'title' : 'icu',
		'location' : 'intl/icu',

		'latest_version_fetch_type' : 'html_re',
		'latest_version_fetch_location' : 'http://site.icu-project.org/download/',
		'latest_version_re' : "<p><b><i>ICU ([0-9.]+) is now available.</i></b>",

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/intl/icu/SVN-INFO",
		'current_version_re': "Relative URL: \^/tags/release-([0-9-]+)/icu4c",
		'current_version_post_alter' : lambda x : x.replace("-", "."),
	},
	{
		'title' : 'brotli',
		'location' : 'modules/brotli',
		'filing_info' : '(When brotli upgrades, see if the current dev branch is master or v0.5. Fix the mozilla update.sh script to output the version (like in #1341895).)',
		'ignore' : '0.5.2', #1340910

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/google/brotli',

		'current_version_fetch_type' : 'hardcoded',
		'current_version_fetch_location': "0.4.0",
	},
	{
		'title' : 'libbz2',
		'location' : 'modules/libbz2',

		'latest_version_fetch_type' : 'html_re',
		'latest_version_fetch_location' : 'http://bzip.org/index.html',
		'latest_version_re' : "The current version is <b>([0-9.]+)</b>",

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/modules/libbz2/src/bzlib.h",
		'current_version_re': "bzip2/libbzip2 version ([0-9.]+) of",
	},
	{
		'title' : 'SRTP',
		'location' : 'netwerk/srtp',
		'ignore' : '2.0.0', # 1230759

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/cisco/libsrtp',

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/netwerk/srtp/src/VERSION",
		'current_version_re': "([0-9\.]+)",
	},
	{
		'title' : 'OTS',
		'location' : 'gfx/ots',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/khaledhosny/ots/',

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/ots/README.mozilla",
		'current_version_re': "Current revision: [0-9a-fA-F]+ \(([0-9\.]+)\)",
	},
	{
		'title' : 'libvpx',
		'location' : 'media/libvpx',

		'latest_version_fetch_type' : 'html_re',
		'latest_version_fetch_location' : 'https://chromium.googlesource.com/webm/libvpx/+refs',
		'latest_version_re' : "Tags</h3><ul class=\"RefList-items\"><li class=\"RefList-item\"><a href=\"/webm/libvpx/\+/v([0-9.]+)\">",

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/media/libvpx/README_MOZILLA",
		'current_version_re': "The git commit ID used was v([0-9.]+)",
	},
	{
		'title' : 'kissfft',
		'location' : 'media/kiss_fft',
		'filing_info' : 'Core:Audio/Video',

		'latest_version_fetch_type' : 'html_re',
		'latest_version_fetch_location' : 'http://hg.code.sf.net/p/kissfft/code',
		'latest_version_re' : "<td class=\"description\"><a href=\"/p/kissfft/code/rev/([0-9a-f]+)\"",


		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/media/kiss_fft/README_MOZILLA",
		'current_version_re': "([0-9a-f]{12})",

		'compare_type' : 'equality'
	},
	{
		'title' : 'freetype2',
		'filing_info' : 'CC:ryanvm',
		'location' : 'modules/freetype2',

		'latest_version_fetch_type' : 'find_in_directory',
		'latest_version_fetch_location' : 'http://download.savannah.gnu.org/releases/freetype/',
		'latest_version_file_prefix_re' : 'freetype-',
		'latest_version_file_suffix_re' : '\.tar\.bz2',

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/modules/freetype2/README",
		'current_version_re': "FreeType ([0-9\.]+)",
	},
	{
		'title' : 'libffi',
		'filing_info' : 'CC:ryanvm Core:js-ctypes',
		'location' : 'js/src/ctypes',
		'ignore' : '3.2.1', #1339534

		'latest_version_fetch_type' : 'html_re',
		'latest_version_fetch_location' : 'https://sourceware.org/libffi/',
		'latest_version_re' : "<b>libffi-([0-9.]+)</b> was released",
		'latest_version_fetch_ssl_verify' : False, #SAN bug on the server I can't reproduce locally

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/js/src/ctypes/libffi/README",
		'current_version_re': "libffi-([0-9\.]+) was",
	},
	{
		'title' : 'jemalloc',
		'filing_info' : 'CC:ryanvm',
		'location' : 'memory/jemalloc',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/jemalloc/jemalloc/',

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/memory/jemalloc/src/VERSION",
		'current_version_re': "([0-9\.]+)-",
	},
	{
		'title' : 'sqlite',
		'filing_info' : 'Toolkit:Storage CC:ryanvm Blocks:1339321 Blocks:previous-update-bug',
		'location' : 'db/sqlite3',
		'ignore' : '3.17.0', #1339110

		'latest_version_fetch_type' : 'html_re',
		'latest_version_fetch_location' : 'https://www.sqlite.org/chronology.html',
		'latest_version_re' : "<h1 align=center>History Of SQLite Releases<\/h1>\s+<center>\s+<table border=0 cellspacing=0>\s+<thead>\s+<tr><th>Date<th><th align='left'>Version\s+<\/thead>\s+<tbody>\s+<tr><td><a href='https:\/\/www\.sqlite\.org\/src\/timeline\?c=[0-9a-z]+\&y=ci'>[0-9-]+<\/a><\/td>\s+<td width='20'><\/td>\s+<td><a href=\"releaselog\/[0-9_]+\.html\">([0-9.]+)<\/a><\/td><\/tr>",

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/old-configure.in",
		'current_version_re': "SQLITE_VERSION=([0-9\.]+)",
	},
	{
		'title' : 'pixman',
		'location' : 'gfx/cairo',
		'ignore' : '0.34.0', #870258

		'latest_version_fetch_type' : 'html_re',
		'latest_version_fetch_location' : 'https://www.cairographics.org/releases/',
		'latest_version_fetch_ssl_verify' : False, #SAN bug on the server I can't reproduce locally
		'latest_version_re' : "LATEST-pixman-([0-9.]+)",

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/cairo/README",
		'current_version_re': "pixman \(([0-9\.]+)\)",
	},
	{
		'title' : 'libav',
		'location' : 'media/libav',
		'filing_info' : 'Core:Audio/Video',
		'ignore' : '12', #1339521

		'latest_version_fetch_type' : 'html_re',
		'latest_version_fetch_location' : 'https://libav.org/download/',
		'latest_version_re' : "<b>([0-9.]+)</b> was released on <i>",
		'latest_version_fetch_ssl_verify' : False, #Think it's a root cert issue? Or maybe an Intermediate issue.

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/media/libav/VERSION",
		'current_version_re': "([0-9\.]+)",
	},
	{
		'title' : 'zlib',
		'location' : 'modules/zlib',

		'latest_version_fetch_type' : 'html_re',
		'latest_version_fetch_location' : 'http://zlib.net/ChangeLog.txt',
		'latest_version_re' : "Changes in ([0-9.]+)",

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/modules/zlib/src/ChangeLog",
		'current_version_re': "Changes in ([0-9.]+)",
	},
	{
		'title' : 'skia',
		'filing_info' : 'Core:Graphics blocks:1210886',
		'location' : 'gfx/skia',
		'ignore' : '57', #1338658

		'latest_version_fetch_type' : 'html_re',
		'latest_version_fetch_location' : 'https://skia.googlesource.com/skia/+/master/include/core/SkMilestone.h',
		'latest_version_re' : '<span class="pln"> SK_MILESTONE <\/span><span class="lit">([0-9]+)<\/span>',
		'latest_version_post_alter' : lambda x : str(int(x)-1),

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/skia/skia/include/core/SkMilestone.h",
		'current_version_re': "SK_MILESTONE ([0-9]+)",
	},
	{
		'title' : 'Harfbuzz',
		'location' : 'gfx/harfbuzz/',
		'filing_info' : 'Core:Graphics:Text CC:ryanvm',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/behdad/harfbuzz/',

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/harfbuzz/README-mozilla",
		'current_version_re': "Current version:\s*([0-9\.]+)",
		'ignore' : '1.4.3' #1342964
	},
	{
		'title' : 'Graphite2',
		'location' : 'gfx/graphite',
		'filing_info' : 'CC:ryanvm',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location': "https://github.com/silnrsi/graphite/",

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/gfx/graphite2/README.mozilla",
		'current_version_re': "This directory contains the Graphite2 library release ([0-9\.]+) from",
	},
	{
		'title' : 'Hunspell',
		'location' : 'extensions/spellcheck/hunspell/',
		'filing_info' : 'CC:ryanvm',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/hunspell/hunspell/',

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/extensions/spellcheck/hunspell/src/README.mozilla",
		'current_version_re': "Hunspell Version:\s*v?([0-9\.]+)",
	},
	#{
	#	'title' : 'Hyphen',
	#	'location' : 'intl/hyphenation/',
	#	'filing_info' : 'CC:ryanvm',

	#	'latest_version_fetch_type' : '',
	#	'latest_version_fetch_location' : 'https://sourceforge.net/projects/hunspell/files/Hyphen/',

	#	'current_version_fetch_type' : 'html_re',
	#	'current_version_fetch_location': "",
	#	'current_version_re': "",
	#},
	{
		'title' : 'Codemirror',
		'filing_info' : 'Firefox: Developer Tools: Source Editor',
		'location' : 'devtools/client/sourceeditor/codemirror/',
		'ignore' : '5.24.2', #1338659

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/codemirror/CodeMirror/',

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/devtools/client/sourceeditor/codemirror/README",
		'current_version_re': "Currently used version is ([0-9\.]+)\. To upgrade",
	},
	{
		'title' : 'pdfjs',
		'location' : 'browser/extensions/pdfjs',
		'allows_ahead' : True,
		'filing_info' : 'CC:ryanvm',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/mozilla/pdf.js',

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/extensions/pdfjs/README.mozilla",
		'current_version_re': "Current extension version is: ([0-9\.]+)",
	},
	{
		'title' : 'ternjs',
		'location' : 'devtools/client/sourceeditor/tern',
		'ignore' : '0.21.0', #1338660

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/ternjs/tern',

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/devtools/client/sourceeditor/tern/README",
		'current_version_re': "Currently used version is ([0-9\.]+)\.",
	},
		{
		'title' : 'libjpeg-turbo',
		'location' : 'media/libjpeg',
		'filing_info' : 'CC:ryanvm',

		'latest_version_fetch_type' : 'github_rss',
		'latest_version_fetch_location' : 'https://github.com/libjpeg-turbo/libjpeg-turbo',

		'current_version_fetch_type' : 'html_re',
		'current_version_fetch_location': "https://hg.mozilla.org/mozilla-central/raw-file/tip/media/libjpeg/MOZCHANGES",
		'current_version_re': "Updated to v([0-9\.]+) release.",
	}
]

################################################################################

bug_message = """
=========================
Update %(title)s to %(latest_version)s
---------
%(filing_info)s Blocks: 1325608
---------
This is a (semi-)automated bug making you aware that there is an available upgrade for an embedded third-party library.

%(title)s is currently at version %(current_version)s in mozilla-central, and the latest version of the library released is %(latest_version)s. 

I fetched the latest version of the library from %(latest_version_fetch_location)s.

You can leave this bug open, and it will be updated if a newer version of the library becomes available. If you close it as WONTFIX, please indicate if you do not wish to receive any future bugs upon new releases of the library.
=========================
"""

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
			result = fetch_and_compare(config)

			if result['status'] != OK:
				return_code = result['status']

		except Exception as e:
			return_code = ERROR
			print "\tCaught an exception processing", config['title']
			print traceback.format_exc()

	sys.exit(return_code)