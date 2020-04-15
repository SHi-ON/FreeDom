#!/usr/bin/env python
import socket
import string
import sys
from time import sleep

try:
    import whois
except ImportError:
    print("ERROR: This script requires the python-whois module to run.")
    print("   You can install it via 'pip install python-whois'")
    sys.exit(0)

# Change top-level domain to check here
TLD = '.com'


def tri_part_dom():
    # 1. Get prefixes and suffixes from input.txt
    suffixes = []
    prefixes = []
    readingPrefixes = False
    f = open('input.txt')
    for l in f:
        line = l.strip()
        if line == '--prefixes':
            readingPrefixes = True
            continue
        elif line == '--suffixes':
            readingPrefixes = False
            continue
        elif not line:
            continue  # Ignore empty lines
        if readingPrefixes:
            prefixes.append(line)
        else:
            suffixes.append(line)
    f.close()

    # 2. create list of domains from prefixes and suffixes
    doms = []
    for pre in prefixes:
        for suff in suffixes:
            doms.append(pre + suff + TLD)

    # 3. Get list of domains that have already found to be free and removed them
    checked_domains = [line.strip() for line in open('checked.txt')]  # Strip out newlines too
    for remove in checked_domains:
        try:
            doms.remove(remove)
        except ValueError:
            pass  # Ignore exceptions

    return doms


def three_letter_dom():
    # three-letter domains examination
    doms = list()
    for l1 in string.ascii_lowercase:
        for l2 in string.ascii_lowercase:
            for l3 in string.ascii_lowercase:
                doms.append(l1 + l2 + l3 + TLD)

    print('size:', len(doms))

    return doms


def four_letter_dom():
    # three-letter domains examination
    doms = list()
    for l1 in string.ascii_lowercase:
        for l2 in string.ascii_lowercase:
            for l3 in string.ascii_lowercase:
                for l4 in string.ascii_lowercase:
                    doms.append(l1 + l2 + l3 + l4 + TLD)

    print('size:', len(doms))

    return doms


def eliminate_checked(doms):
    with open('checked.txt') as handle:
        content = list(map(str.rstrip, handle.readlines()))
    filtered = list(filter(lambda x: x not in content, doms))

    print('size after the remove:', len(filtered))

    return filtered


def report_failures(d):
    with open('failed.txt', 'a') as h_failed:
        h_failed.write(d + '\n')


# d = tri_part_dom()
# d = four_letter_dom()
d = three_letter_dom()

domains = eliminate_checked(d)

# 4. Check list of domains and write to file

for domain in domains:

    sleep(0.5)  # Too many requests lead to incorrect responses
    print(' Checking: ' + domain),  # Comma means no newline is printed

    try:
        w = whois.whois(domain)
        print('\tTAKEN')
        with open('checked.txt', 'a') as h_checked:
            h_checked.write(domain + '\n')
    except whois.parser.PywhoisError:
        # Exception means that the domain is free
        print('\tFREE')
        with open('free-domains.txt', 'a') as h_free:
            h_free.write(domain + '\n')
    except ConnectionResetError:
        print('~>~>~> Connection reset (ConnectionResetError) error has been thrown')
        report_failures(domain)
    except socket.timeout:
        print('|>|>|> Time out (socket.timeout) error has been thrown')
        report_failures(domain)
    except ConnectionRefusedError:
        print('+>+>+> Connection refused (ConnectionRefusedError) error has been thrown')
        report_failures(domain)

print("DONE!")
