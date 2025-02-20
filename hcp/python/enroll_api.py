#!/usr/bin/python3

# A crude way to perform these tasks directly (using curl) is;
#
# add:     curl -v -F ekpub=@</path/to/ek.pub> \
#               -F hostname=<hostname> \
#               <enrollsvc-URL>/v1/add
#
# query:   curl -v -G -d ekpubhash=<hexstring> \
#               <enrollsvc-URL>/v1/query
#
# delete:  curl -v -F ekpubhash=<hexstring> \
#               <enrollsvc-URL>/v1/delete
#
# find:    curl -v -G -d hostname_suffix=<hostname_suffix> \
#               <enrollsvc-URL>/v1/find

import json
import requests
import os
import sys
import argparse

# Handler functions for the subcommands (add, query, delete, find)
# They all return a 2-tuple of {result,json}, where result is True iff the
# operation was successful.

def enroll_add(args):
    form_data = {
        'ekpub': ('ek.pub', open(args.ekpub, 'rb')),
        'hostname': (None, args.hostname)
    }
    response = requests.post(args.api + '/v1/add', files=form_data)
    jr = json.loads(response.content)
    try:
        rcode = jr['returncode']
    except KeyError:
        print("Error, response has no 'returncode'")
        print(jr)
        rcode = -1
    if (rcode != 0):
        return False, jr
    return True, jr

def do_query_or_delete(args, is_delete):
    if is_delete:
        form_data = { 'ekpubhash': (None, args.ekpubhash) }
        response = requests.post(args.api + '/v1/delete', files=form_data)
    else:
        form_data = { 'ekpubhash': args.ekpubhash }
        response = requests.get(args.api + '/v1/query', params=form_data)
    jr = json.loads(response.content)
    return True, jr

def enroll_query(args):
    return do_query_or_delete(args, False)

def enroll_delete(args):
    return do_query_or_delete(args, True)

def enroll_find(args):
    form_data = { 'hostname_suffix': args.hostname_suffix }
    response = requests.get(args.api + '/v1/find', params=form_data)
    jr = json.loads(response.content)
    return True, jr

if __name__ == '__main__':

    # Wrapper 'enroll' command, using argparse

    enroll_desc = 'API client for Enrollment Service management interface'
    enroll_epilog = """
    If the URL for the Enrollment Service's management API is not supplied on the
    command line (via '--api'), it will fallback to using the 'ENROLLSVC_API_URL'
    environment variable.

    To see subcommand-specific help, pass '-h' to the subcommand.
    """
    enroll_help_api = 'base URL for management interface'
    parser = argparse.ArgumentParser(description=enroll_desc,
                                     epilog=enroll_epilog)
    parser.add_argument('--api', metavar='<URL>',
                        default=os.environ.get('ENROLLSVC_API_URL'),
                        help=enroll_help_api)

    subparsers = parser.add_subparsers()

    # Subcommand details

    add_help = 'Enroll a {TPM,hostname} 2-tuple'
    add_epilog = """
    The 'add' subcommand invokes the '/v1/add' handler of the Enrollment Service's
    management API, to trigger the enrollment of a TPM+hostname 2-tuple. The
    provided 'ekpub' file should be either in the PEM format (text) or TPM2B_PUBLIC
    (binary). The provided hostname is registered in the TPM enrollment in order to
    create a binding between the TPM and its corresponding host - this should not be
    confused with the '--api' argument, which provides a URL to the Enrollment
    Service!
    """
    add_help_ekpub = 'path to the public key file for the TPM\'s Endorsement Key'
    add_help_hostname = 'hostname to be enrolled with (and bound to) the TPM'
    parser_a = subparsers.add_parser('add', help=add_help, epilog=add_epilog)
    parser_a.add_argument('ekpub', help=add_help_ekpub)
    parser_a.add_argument('hostname', help=add_help_hostname)
    parser_a.set_defaults(func=enroll_add)

    query_help = 'Query (and list) enrollments based on prefix-search of hash(EKpub)'
    query_epilog = """
    The 'query' subcommand invokes the '/v1/query' handler of the Enrollment
    Service's management API, to retrieve an array of enrollment entries matching
    the query criteria. Enrollment entries are indexed by 'ekpubhash', which is a
    hash of the public half of the TPM's Endorsement Key. The query parameter is a
    hexidecimal string, which is used as a prefix search for the query. Passing an
    empty string will return all enrolled entries in the database, or by providing 1
    or 2 hexidecimal characters approximately 1/16th or 1/256th of the enrolled
    entries (respectively) will be returned. To query a specific entry, the query
    parameter should contain enough of the ekpubhash to uniquely distinguish it from
    all others. (Usually, this is significantly fewer characters than the full
    ekpubhash value.)
    """
    query_help_ekpubhash = 'hexidecimal prefix (empty to return all enrollments)'
    parser_q = subparsers.add_parser('query', help=query_help, epilog=query_epilog)
    parser_q.add_argument('ekpubhash', help=query_help_ekpubhash)
    parser_q.set_defaults(func=enroll_query)

    delete_help = 'Delete enrollments based on prefix-search of hash(EKpub)'
    delete_epilog = """
    The 'delete' subcommand invokes the '/v1/delete' handler of the Enrollment
    Service's management API, to delete (and retrieve) an array of enrollment
    entries matching the query criteria. The 'delete' subcommand supports precisely
    the same parameterisation as 'query', so please consult the 'query' help for
    more detail. Both commands return an array of enrollment entries that match the
    query parameter. The only distinction is that the 'delete' command,
    unsurprisingly, will also delete the matching enrollment entries.
    """
    delete_help_ekpubhash = 'hexidecimal prefix (empty to delete all enrollments)'
    parser_d = subparsers.add_parser('delete', help=delete_help, epilog=delete_epilog)
    parser_d.add_argument('ekpubhash', help=delete_help_ekpubhash)
    parser_d.set_defaults(func=enroll_delete)

    find_help = 'Find enrollments based on suffix-search for hostname'
    find_epilog = """
    The 'find' subcommand invokes the '/v1/find' handler of the Enrollment Service's
    management API, to retrieve an array of enrollment entries whose hostnames match
    the given parameter. Unlike 'query' which searches based on the hash of the
    TPM's EK public key, 'find' looks at the hostname each TPM is enrolled for. This
    is a suffix search, meaning it will match on enrollments whose hostnames end
    with the provided string. E.g. "a.xyz" will match "gamma.xyz" and "delta.xyz"
    but not "a.xyz.com". If the string is zero-length, the command matches on all
    enrolled entries in the database. Note, the array returned from this command
    consists of solely of 'ekpubhash' values for matching enrollments. To obtain
    details about the matching entries (including the hostnames that matched),
    subsequent API calls (using 'query') should be performed using the 'ekpubhash'
    fields.
    """
    find_help_suffix = 'hostname suffix (empty to return all enrollments)'
    parser_f = subparsers.add_parser('find', help=find_help, epilog=find_epilog)
    parser_f.add_argument('hostname_suffix', help=find_help_suffix)
    parser_f.set_defaults(func=enroll_find)

    # Process the command-line
    args = parser.parse_args()
    if not args.api:
        print("Error, no API URL was provided.")
        sys.exit(-1)

    # Dispatch
    result, json = args.func(args)
    if not result:
        print("Error, API returned failure")
        sys.exit(-1)
    print(json)
