import os
import sys
import requests
import logging
import csv
import json

from os.path import split as pathsplit
from urllib.parse import urljoin, urlparse
from configparser import ConfigParser

from collections import defaultdict


GITHUB_API = 'https://api.github.com/'
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_HEADERS = {
  'Accept': 'application/vnd.github+json',
  'Authorization': f'Bearer {GITHUB_TOKEN}',
  'X-GitHub-Api-Version': '2022-11-28',
}
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())


def get_sbom(project, url):
    # /repos/OWNER/REPO/dependency-graph/sbom
    path = urlparse(url).path
    owner, repo = pathsplit(path)[0:2]
    api_url = urljoin(GITHUB_API, f'repos/{owner}/{repo}dependency-graph/sbom')
    LOGGER.info('Fetching SBOM for %s', project)
    r = requests.get(api_url, headers=GITHUB_HEADERS)
    assert r.status_code == 200, 'Invalid status code %i' % r.status_code
    return r.json()


def get_projects(path='./projects.ini'):
    # NOTE: read from .ini file.
    c = ConfigParser()
    c.read(path)
    for project in c.sections():
        overrides = {}
        url = c[project]['url']
        for package in c[project].keys():
            if package == 'url':
                continue
            version, license = c[project][package].split(',')
            overrides[package] = (version, license)
        yield project, url, overrides


def merge_dependencies(new, overrides, old=None):
    old = old or defaultdict(list)
    for i, package in enumerate(new['sbom']['packages']):
        if i == 0:
            # Skip self
            continue
        package_name = package['name']
        try:
            version, license = overrides[package_name]
        except KeyError:
            version = package['versionInfo']
            license = package['licenseConcluded']
            license = license.replace('NOASSERTION', 'Unknown')
        old[package_name].append((version, license))
    return old


def print_record_csv(f, record):
    csv = ", ".join([str(s) for s in record.values()]) + '\n'
    f.write(csv)


def print_record_json(f, record):
    json.dump(record, f)
    f.write('\n')


def get_line_printer(format):
    assert format in ('csv', 'json'), 'Invalid format %s' % format
    return print_record_csv if format == 'csv' else print_record_json


def print_report(data, format='csv', f=sys.stdout):
    line_printer = get_line_printer(format)

    for package_name, v_and_l in data.keys():
        versions = set()
        licenses = set()
        for version, license in v_and_l:
            versions.add(version)
            licenses.add(license)
        line_printer(f, {
            'package': package_name,
            'versions': ', '.join(versions),
            'licenses': ', '.join(licenses),
        })
    f.flush()


def print_summary(data, format='csv', f=sys.stdout):
    line_printer = get_line_printer(format)
    licenses = defaultdict(int)

    for package_name, v_and_l in data.items():
        for version, license in v_and_l:
            licenses[license] += 1

    for license, count in licenses.items():
        line_printer(f, {
            'license': license,
            'count': count,
        })