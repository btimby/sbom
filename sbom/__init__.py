import os
import sys
import requests
import logging
import csv
import json

from json.decoder import JSONDecodeError
from os.path import split as pathsplit
from urllib.parse import urljoin, urlparse
from configparser import ConfigParser

from collections import defaultdict


API_URL = 'https://api.github.com/'
API_TOKEN = os.getenv('API_TOKEN')
GITHUB_HEADERS = {
  'Accept': 'application/vnd.github+json',
  'Authorization': f'Bearer {API_TOKEN}',
  'X-GitHub-Api-Version': '2022-11-28',
}
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())


def get_sbom(project, url):
    # api path: /repos/OWNER/REPO/dependency-graph/sbom
    if not API_TOKEN:
        raise Exception('No github token, specify env. variable API_TOKEN=???')
    path = urlparse(url).path
    owner, repo = pathsplit(path)[0:2]
    api_url = urljoin(API_URL, f'repos/{owner}/{repo}dependency-graph/sbom')
    LOGGER.info('Fetching SBOM for %s', project)
    r = requests.get(api_url, headers=GITHUB_HEADERS)
    assert r.status_code == 200, 'Invalid status code %i' % r.status_code
    return r.json()


def parse_overrides(overrides):
    try:
        override = json.loads(overrides)
    except JSONDecodeError:
        LOGGER.exception(overrides)
        raise

    package = override.pop('name')

    return package, override


def build_package_url(purl):
    if purl.startswith('pkg:npm/'):
        return f'https://www.npmjs.com/package/{purl[8:].split("@")[0]}/'
    if purl.startswith('pkg:pypi/'):
        return f'https://pypi.org/project/{purl[9:].split("@")[0]}/'
    return purl


def parse_url(refs):
    if refs is None:
        return None
    for ref in refs:
        if ref['referenceType'] == 'purl':
            return build_package_url(ref['referenceLocator'])


def get_projects(path='./projects.ini'):
    # NOTE: read from .ini file.
    c = ConfigParser()
    c.read(path)
    for project in c.sections():
        overrides = defaultdict(dict)
        url = c[project]['url']
        for key in c[project].keys():
            if not key.startswith('override'):
                continue
            package, override = parse_overrides(c[project][key])
            overrides[package].update(override)
        yield project, url, overrides


def merge_dependencies(new, overrides, old=None):
    old = old or defaultdict(dict)
    for i, package in enumerate(new['sbom']['packages']):
        if i == 0:
            # Skip self
            continue
        package_name = package['name']

        version = package['versionInfo']
        license = package['licenseConcluded']
        license = license.replace('NOASSERTION', 'Unknown')
        url = parse_url(package.get('externalRefs'))

        # NOTE: heuristic:
        if version.startswith('^') and license == 'Unknown':
            continue

        try:
            override = overrides[package_name]
        except KeyError:
            pass

        else:
            version = override.get('version', version)
            license = override.get('license', license)
            url = override.get('url', url)

        old[package_name][version] = (license, url)

    for package_name, override in overrides.items():
        if package_name not in old:
            old[package_name][override['version']] = (
                override.get('license'),
                override.get('url'),
            )

    return old


def print_record_csv(f, record):
    values = []
    for item in record.values():
        item = str(item)
        item = f'"{item}"' if ',' in item else item
        values.append(item)
    csv = ", ".join(values) + '\n'
    f.write(csv)


def print_record_json(f, record):
    json.dump(record, f)
    f.write('\n')


def get_line_printer(format):
    assert format in ('csv', 'json'), 'Invalid format %s' % format
    return print_record_csv if format == 'csv' else print_record_json


def print_report(data, format='csv', f=sys.stdout):
    line_printer = get_line_printer(format)

    for package_name, vlu in data.items():
        versions, licenses, urls = set(), set(), set()

        for version, (license, url) in vlu.items():
            if version is not None:
                versions.add(version)
            if license is not None:
                licenses.add(license)
            if url is not None:
                urls.add(url)

        line_printer(f, {
            'package': package_name,
            'versions': ', '.join(versions),
            'licenses': ', '.join(licenses),
            'urls': ', '.join(urls),
        })

    f.flush()


def print_summary(data, format='csv', f=sys.stdout):
    line_printer = get_line_printer(format)
    licenses = defaultdict(int)

    for package_name, vlu in data.items():
        for version, (license, url) in vlu.items():
            licenses[license] += 1

    for license, count in licenses.items():
        line_printer(f, {
            'license': license,
            'count': count,
        })
