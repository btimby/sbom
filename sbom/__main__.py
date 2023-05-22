import sys
import logging
import argparse

from urllib.parse import urlparse
from os.path import split as pathsplit
from pprint import pprint

from sbom import (
    get_projects, get_sbom, merge_dependencies, print_report, print_summary,
)


LOGGER = logging.getLogger()
LOGGER.addHandler(logging.NullHandler())


def main(args):
    deps = None

    if args.url:
        path_parts = [s for s in urlparse(args.url).path.split('/') if s]
        project_name = path_parts[-1]
        projects = [(project_name, args.url, {})]

    else:
        projects = get_projects()

    for project, url, overrides in projects:
        sbom = get_sbom(project, url)
        deps = merge_dependencies(sbom, overrides, old=deps)

    output = open(args.output, 'w') if args.output else sys.stdout

    if args.summary:
        print_summary(deps, format=args.format, f=output)
    else:
        print_report(deps, format=args.format, f=output)

    if args.output:
        output.close()


if __name__ == '__main__':
    LOGGER.setLevel(logging.DEBUG)
    LOGGER.addHandler(logging.StreamHandler())

    parser = argparse.ArgumentParser(
        prog='sbom',
        description='Prints combined version / license information for '
                    'github projects',
    )

    parser.add_argument('-s', '--summary', action='store_true')
    parser.add_argument(
        '-f', '--format', choices=('csv', 'json',), default='csv')
    parser.add_argument('-o', '--output')
    parser.add_argument('-u', '--url')

    args = parser.parse_args()

    main(args)
