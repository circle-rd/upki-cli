#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""
UPKI CLI Client.

This is the main entry point for the UPKI Command Line Interface client.
"""

import os
import sys
import re
import argparse
import logging
from typing import Any

import client


def main(argv):
    BASE_DIR = os.path.join(os.path.expanduser("~"), ".upki")
    LOG_FILE = ".cli.log"
    LOG_LEVEL = logging.INFO
    VERBOSE = True
    OUTPUT = "cli"
    PEM = False
    NO_PASS = False

    parser = argparse.ArgumentParser(description="µPki-CLI is the µPKI client.")
    parser.add_argument("-q", "--quiet", help="Output less infos", action="store_true")
    parser.add_argument("-d", "--debug", help="Enable debug mode", action="store_true")
    parser.add_argument(
        "-j", "--json", help="Output result in json", action="store_true"
    )
    parser.add_argument("-u", "--url", help="Define the RA url", required=True)
    parser.add_argument(
        "-p",
        "--path",
        help="Set the directory path where private keys, csr and certificates are stored. (Default: {p})".format(
            p=BASE_DIR
        ),
    )

    # Allow subparsers
    subparsers = parser.add_subparsers(title="commands")

    parser_add = subparsers.add_parser("add", help="Add a node to certify.")
    parser_add.set_defaults(which="add")
    parser_add.add_argument(
        "-n", "--name", help="Define the requested CN for node", default=None
    )
    parser_add.add_argument(
        "-c",
        "--chrome",
        help="Add node certificate to Chrome",
        action="store_true",
        default=False,
    )
    parser_add.add_argument(
        "-f",
        "--firefox",
        help="Add node certificate to Firefox",
        action="store_true",
        default=False,
    )
    parser_add.add_argument(
        "-p", "--profile", help="Set the profile name for node", default=None
    )
    parser_add.add_argument(
        "--p12",
        help="Generate a p12 certificate file (default: .pem only)",
        action="store_true",
        default=False,
    )
    parser_add.add_argument(
        "--passwd",
        help="Protect p12 file with pass (default: False)",
        action="store",
        default=None,
    )

    parser_renew = subparsers.add_parser("renew", help="Renew nodes registered.")
    parser_renew.set_defaults(which="renew")

    parser_crl = subparsers.add_parser("crl", help="Regenerate CRL.")
    parser_crl.set_defaults(which="crl")

    parser_list = subparsers.add_parser("list", help="List nodes registered.")
    parser_list.set_defaults(which="list")

    parser_delete = subparsers.add_parser(
        "delete", help="Delete node from local db (does not impact server)."
    )
    parser_delete.set_defaults(which="delete")
    parser_delete.add_argument(
        "-n", "--name", help="Define the requested CN for node", default=None
    )
    parser_delete.add_argument(
        "-p", "--profile", help="Set the profile name for node", default=None
    )

    args = parser.parse_args()

    try:
        # User MUST call upki with a command
        args.which
    except AttributeError:
        parser.print_help()
        sys.exit(1)

    # Parse common options
    if args.quiet:
        VERBOSE = False
        LOG_LEVEL = logging.ERROR

    if args.debug:
        LOG_LEVEL = logging.DEBUG

    if args.json:
        OUTPUT = "json"

    # Ensure directory exists
    if not os.path.isdir(BASE_DIR):
        try:
            os.makedirs(BASE_DIR)
        except OSError as err:
            raise Exception(err)

    LOG_FILE = os.path.join(BASE_DIR, LOG_FILE)

    try:
        # Generate logger object
        logger = client.UPKILogger(
            LOG_FILE, LOG_LEVEL, proc_name="upki CLI", verbose=VERBOSE
        )
    except Exception as err:
        raise Exception("Unable to setup logger: {e}".format(e=err))

    # Meta information
    dirname = os.path.dirname(__file__)

    # Retrieve all metadata from project
    with open(os.path.join(dirname, "__metadata.py"), "rt") as meta_file:
        metadata = dict(
            re.findall(r"^__([a-z]+)__ = ['\"]([^'\"]*)['\"]", meta_file.read(), re.M)
        )

    logger.info("\t\t..:: µPKI Client ::..", color="WHITE", light=True)
    logger.info("version: {v}".format(v=metadata["version"]), color="WHITE")

    try:
        bot = client.Bot(logger, args.url, BASE_DIR, verbose=VERBOSE)
    except Exception as err:
        logger.error(err)
        return False

    if args.which == "add":
        # Url is mandatory for node addition
        if not args.url:
            raise Exception("You MUST set an url for node certificate retrieval")

        try:
            # Register node in local config
            bot.add_node(
                args.name,
                args.profile,
                p12=args.p12,
                passwd=args.passwd,
                firefox=args.firefox,
                chrome=args.chrome,
            )
        # Does not block code when node or certificate exist
        except RuntimeError as err:
            logger.error(err)
            return False
        # Exit sys on all other conditions
        except Exception as err:
            logger.error(err)
            sys.exit(1)
    elif args.which == "renew":
        try:
            # Renew all nodes in config
            bot.renew()
        except Exception as err:
            logger.error(err)
            sys.exit(1)
    elif args.which == "crl":
        # Url is mandatory for CRL retrieval
        if not args.url:
            raise Exception("You MUST set an url for CRL retrieval")
        try:
            # Regenerate CRL file
            bot.crl()
        except Exception as err:
            logger.error(err)
            sys.exit(1)
    elif args.which == "list":
        try:
            # List all nodes in config
            bot.list()
        except Exception as err:
            logger.error(err)
            sys.exit(1)
    elif args.which == "delete":
        try:
            # Delete node in config
            bot.delete(args.name, args.profile)
        except Exception as err:
            logger.error(err)
            sys.exit(1)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        sys.stdout.write("\nBye.\n")
