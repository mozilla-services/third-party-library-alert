#!/usr/bin/env python

import os
import re
import sys
import json
import base64
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
	if config['latest_version_fetch_type'] == 'github_rss' and \
	   not config['latest_version_fetch_location'].endswith('/'):
		config['latest_version_fetch_location'] += '/'

	if 'current_version_fetch_location' in config and \
		config['current_version_fetch_location'].startswith('https://hg.mozilla.org/') \
		and not config['current_version_fetch_location'].startswith('https://hg.mozilla.org/mozilla-central/raw-file/tip/'):
		raise Exception("current_version_fetch_location (" + config['current_version_fetch_location'] + ") does not appear to be a raw hg.mozilla link.")

	if 'filing_info' not in config:
		config['filing_info'] = ''
	if 'most_recent_bug' not in config:
		config['most_recent_bug'] = ''

	if 'current_version_fetch_ssl_verify' not in config:
		config['current_version_fetch_ssl_verify'] = True
	if 'latest_version_fetch_ssl_verify' not in config:
		config['latest_version_fetch_ssl_verify'] = True

	if 'compare_type' not in config:
		config['compare_type'] = 'version'

	if 'print_additional_library_info' not in config:
		config['print_additional_library_info'] = ''

	for i in ['current_version_post_alter', 'latest_version_post_alter', 'print_latest_version_fetch_location_munge']:
		if i in config:
			config[i] = eval(config[i])

	return config

def munge_config_for_printing(config):
	if 'print_latest_version_fetch_location_munge' in config:
		config['latest_version_fetch_location'] = \
			config['print_latest_version_fetch_location_munge'](config['latest_version_fetch_location'])

	return config

################################################################################

def _fetch_html_re(fetch_type, fetch_location, fetch_ssl_verify, regular_expression):
	flags = re.DOTALL if fetch_type == 'dotall_html_re' else 0

	t = requests.get(fetch_location, verify=fetch_ssl_verify)
	if fetch_type == 'html_re_base64':
		searchtext = base64.b64decode(t.text)
	else:
		searchtext = t.text

	m = re.search(regular_expression, searchtext, flags)
	if m:
		matched_text = m.groups(0)[0]
		return matched_text 
	else:
		raise Exception(u"Could not match the regular expression '" + regular_expression + u"' in the text\n\n" + searchtext)

################################################################################

def get_mozilla_version(config):
	if config['current_version_fetch_type'] == 'html_re':
		current_version = _fetch_html_re(config['current_version_fetch_type'], 
			config['current_version_fetch_location'],
			config['current_version_fetch_ssl_verify'], 
			config['current_version_re'])
	elif config['current_version_fetch_type'] == 'hardcoded':
		current_version = config['current_version_fetch_location']
	elif config['current_version_fetch_type'] == 'list':
		raise Exception("List not implemented for Mozilla")
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

def _latest_version_list(config):
	#Find all files with a commit newer than the current version date, but put the 'latest' version as the most recent
	min_value = datetime.datetime.strptime("2000-01-01T12:00:00Z", "%Y-%m-%dT%H:%M:%SZ")
	newest_latest_version = min_value

	for i in config['latest_version_fetch_location_list']:
		this_latest_version = _fetch_html_re('html_re',
			config['latest_version_fetch_location_base'] + i,
			config['latest_version_fetch_ssl_verify'],
			config['latest_version_re'])
		this_latest_version_date = datetime.datetime.strptime(this_latest_version, config['latest_version_date_format_string'])

		fake_config = {
			'current_version' : config['current_version'],
			'current_version_date_format_string' : config['current_version_date_format_string'],
			'latest_version' : this_latest_version,
			'latest_version_date_format_string' : config['latest_version_date_format_string'],
			'compare_date_lag' : 0,
			'verbose' : False
		}
		if newest_latest_version == min_value:
			newest_latest_version = this_latest_version
			config['latest_version_fetch_location'] = config['latest_version_fetch_location_base'] + i
		elif datetime.datetime.strptime(newest_latest_version, config['latest_version_date_format_string']) < this_latest_version_date:
			newest_latest_version = this_latest_version
			config['latest_version_fetch_location'] = config['latest_version_fetch_location_base'] + i

		if _compare_type_date(fake_config) == UPDATE:
			if 'latest_version_addition_info_re' in config:
				if 'print_additional_library_info' not in config:
					config['print_additional_library_info'] = ""
				config['print_additional_library_info'] += \
					"\n-----------------------\nMost Recent Commit Message for " + \
					i + ":\n" + \
					_fetch_html_re('html_re',
					config['latest_version_fetch_location_base'] + i,
					config['latest_version_fetch_ssl_verify'],
					config['latest_version_addition_info_re'])
	return newest_latest_version


def get_latest_version(config):
	if config['latest_version_fetch_type'] == 'github_rss':
		latest_version = _latest_version_github_rss(config)
	elif config['latest_version_fetch_type'] == 'hardcoded':
		latest_version = config['latest_version_fetch_location']
	elif config['latest_version_fetch_type'] == 'list':
		if config['compare_type'] != 'date':
			raise Exception("Lsit type is only supported with Date Comparison")
		latest_version = _latest_version_list(config)
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

	td = config['latest_version'] - config['current_version']
	td = td + -2*td if td < datetime.timedelta() else td #Handle negatives (we kind of ignore timezones...)
	if td >= datetime.timedelta(days=config['compare_date_lag']):
		status = UPDATE
	else:
		if config['latest_version'] != config['current_version'] and config['verbose']:
			print"\tIgnoring a new commit that is not more than", config['compare_date_lag'], "days old"
		status = OK
	return status

################################################################################
def read_json_file():
	f = open("libraries.json")
	almost_json = "".join(f.readlines())
	almost_json = re.sub(r'#.+', '', almost_json)
	try:
		LIBRARIES = json.loads(almost_json)
	except:
		print "Error decoding json:"
		print almost_json
	return LIBRARIES

def fetch_and_compare(config):
	config['current_version'] = get_mozilla_version(config)
	config['latest_version'] = get_latest_version(config)
	
	should_ignore = False
	if config['compare_type'] == 'version':
		status = _compare_type_version(config)
		if status != OK and 'ignore' in config and config['latest_version'] == config['ignore']:
			if 'ignore_until' in config:
				if datetime.datetime.now() < config['ignore_until']:
					should_ignore = True
			else:
				should_ignore = True

	elif config['compare_type'] == 'equality':
		status = _compare_type_equality(config)
		if status != OK and 'ignore' in config and config['latest_version'] == config['ignore']:
			if 'ignore_until' in config:
				if datetime.datetime.now() < config['ignore_until']:
					should_ignore = True
			else:
				should_ignore = True

	elif config['compare_type'] == 'date':
		status = _compare_type_date(config)
		if status == UPDATE and 'ignore' in config:
			ignore_date = datetime.datetime.strptime(config['ignore'], config['ignore_date_format_string'])
			if config['latest_version'] - ignore_date <= datetime.timedelta(days=config['compare_date_lag']):
				if 'ignore_until' in config:
					if datetime.datetime.now() < config['ignore_until']:
						should_ignore = True
				else:
					should_ignore = True

	else:
		raise Exception("Unknown comparison type: " + str(config['compare_type']))

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

				config = munge_config_for_printing(config)
				print bug_message % config
		
		else:
			if config['verbose']:
				print "\tCurrent version (" + str(config['current_version']) + ") is behind latest (" + str(config['latest_version']) + ")"

			config = munge_config_for_printing(config)
			print bug_message % config
	
	config['status'] = status

	return config

################################################################################

bug_message = """
=========================
Update %(title)s to %(latest_version)s
---------
%(filing_info)s 
Most Recent: %(most_recent_bug)s
---------
This is a (semi-)automated bug making you aware that there is an available upgrade for an embedded third-party library. You can leave this bug open, and it will be updated if a newer version of the library becomes available. If you close it as WONTFIX, please indicate if you do not wish to receive any future bugs upon new releases of the library.

%(title)s is currently at version %(current_version)s in mozilla-central, and the latest version of the library released is %(latest_version)s. 

I fetched the latest version of the library from %(latest_version_fetch_location)s.

%(print_additional_library_info)s
=========================
"""

if __name__ == "__main__":
	verbose = False
	if '-v' in sys.argv:
		verbose = True

	if len(sys.argv) > 1 and sys.argv[1] != '-v':
		verbose = True
		libraries = sys.argv[1:]
	else:
		libraries = None

	return_code = OK

	LIBRARIES = read_json_file()

	for l in LIBRARIES:
		if libraries and l['title'] not in libraries:
			continue

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