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


def parse_overrides(overrides):
    package, override = None, {}
    for key, value in zip(['package', 'version', 'license', 'url'], overrides.split(',')):
        if key == 'package':
            package = value.strip()
        else:
            override[key] = value.strip()

    return package, override


def build_package_url(purl):
    if purl.startswith('pkg:npm/'):
        return f'https://www.npmjs.com/package/{purl[8:]}/'
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
    old = old or defaultdict(list)
    for i, package in enumerate(new['sbom']['packages']):
        if i == 0:
            # Skip self
            continue
        package_name = package['name']

        version = package['versionInfo']
        license = package['licenseConcluded']
        license = license.replace('NOASSERTION', 'Unknown')
        url = parse_url(package.get('externalRefs'))

        try:
            override = overrides[package_name]
        except KeyError:
            pass

        else:
            version = override.get('version', version)
            license = override.get('license', license)
            url = override.get('url', url)

        old[package_name].append((version, license, url))

    for package_name, override in overrides.items():
        if package_name not in old:
            old[package_name].append((
                override.get('version'),
                override.get('license'),
                override.get('url'),
            ))

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

        for version, license, url in vlu:
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
        for version, license, url in vlu:
            licenses[license] += 1

    for license, count in licenses.items():
        line_printer(f, {
            'license': license,
            'count': count,
        })