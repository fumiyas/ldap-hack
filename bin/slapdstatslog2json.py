#!/usr/bin/env python3
##
## OpenLDAP: Convert slapd stats log to JSON
## Copyright (c) SATOH Fumiyasu @ OSS Technology Corp., Japan
##
## License: GNU General Public License version 3
##
## -*- coding: utf-8 -*- vim:shiftwidth=4:expandtab:

import logging
import sys
import re
import json

logger = logging.getLogger(__name__)

scope_by_n = {
    0: 'Base',
    1: 'Onelevel',
    2: 'Subtree',
    3: 'Children',
}
deref_by_n = {
    0: 'Never',
    1: 'Searching',
    2: 'Finding',
    3: 'Always',
}
method_by_n = {
    0x00: 'None',
    0x80: 'Simple',
    0xA3: 'SASL',
}
error_text_by_n = {
    0x00: 'SUCCESS',
    0x01: 'OPERATIONS_ERROR',
    0x02: 'PROTOCOL_ERROR',
    0x03: 'TIMELIMIT_EXCEEDED',
    0x04: 'SIZELIMIT_EXCEEDED',
    0x05: 'COMPARE_FALSE',
    0x06: 'COMPARE_TRUE',
    0x07: 'AUTH_METHOD_NOT_SUPPORTED',
    0x08: 'STRONG_AUTH_REQUIRED',
    0x09: 'PARTIAL_RESULTS',
    0x0A: 'REFERRAL',
    0x0B: 'ADMINLIMIT_EXCEEDED',
    0x0C: 'UNAVAILABLE_CRITICAL_EXTENSION',
    0x0D: 'CONFIDENTIALITY_REQUIRED',
    0x0E: 'SASL_BIND_IN_PROGRESS',
    ## Attribute errors
    0x10: 'NO_SUCH_ATTRIBUTE',
    0x11: 'UNDEFINED_TYPE',
    0x12: 'INAPPROPRIATE_MATCHING',
    0x13: 'CONSTRAINT_VIOLATION',
    0x14: 'TYPE_OR_VALUE_EXISTS',
    0x15: 'INVALID_SYNTAX',
    ## Name errors
    0x20: 'NO_SUCH_OBJECT',
    0x21: 'ALIAS_PROBLEM',
    0x22: 'INVALID_DN_SYNTAX',
    0x23: 'IS_LEAF',
    0x24: 'ALIAS_DEREF_PROBLEM',
    ## Security errors
    0x2F: 'X_PROXY_AUTHZ_FAILURE',
    0x30: 'INAPPROPRIATE_AUTH',
    0x31: 'INVALID_CREDENTIALS',
    0x32: 'INSUFFICIENT_ACCESS',
    ## Service errors
    0x33: 'BUSY',
    0x34: 'UNAVAILABLE',
    0x35: 'UNWILLING_TO_PERFORM',
    0x36: 'LOOP_DETECT',
    ## Update errors
    0x40: 'NAMING_VIOLATION',
    0x41: 'OBJECT_CLASS_VIOLATION',
    0x42: 'NOT_ALLOWED_ON_NONLEAF',
    0x43: 'NOT_ALLOWED_ON_RDN',
    0x44: 'ALREADY_EXISTS',
    0x45: 'NO_OBJECT_CLASS_MODS',
    0x46: 'RESULTS_TOO_LARGE',
    0x47: 'AFFECTS_MULTIPLE_DSAS',
    ## Other erros
    0x4C: 'VLV_ERROR',
    0x50: 'OTHER',
}

re_line = re.compile(
    r'(?P<prefix>.*?): conn=(?P<conn>\d+)'
    r' (?P<what>fd|op)=(?P<id>[0-9]+)'
    r' (?P<chunk>.*)'
    '$'
    )

re_bind_method = re.compile(
    r'BIND'
    r' dn="(?P<dn>[^"]*)"'
    r' method=(?P<method_n>\d+)'
    '$'
)
re_bind_authcid = re.compile(
    r'BIND'
    r' authcid="(?P<authcid>[^"]*)"'
    r' authzid="(?P<authzid>[^"]*)"'
    '$'
)
re_bind_mech = re.compile(
    r'BIND'
    r' (dn="(?P<dn>[^"]*)"|anonymous)'
    r' mech=(?P<mech>\w+)'
    r'( sasl_ssf=(?P<sasl_ssf>\d+))?'
    r' ssf=(?P<ssf>\d+)'
    '$'
)

re_search_base = re.compile(
    r'SRCH'
    r' base="(?P<base>[^"]*)"'
    r' scope=(?P<scope_n>\d+)'
    r' deref=(?P<deref_n>\d+)'
    r' filter="(?P<filter>.*)"'
    '$'
)

re_modify_dn = re.compile(
    r'MOD'
    r' dn="(?P<dn>[^"]*)"'
    '$'
)


re_result = re.compile(
    r'RESULT'
    r'( tag=(?P<tag>\d+))?'
    r'( oid=(?P<oid>\W*))?'
    r' err=(?P<error>\d+)'
    r' text=(?P<text>.*)'
    '$'
)
re_search_result = re.compile(
    r'SEARCH RESULT'
    r' tag=(?P<tag>\d+)'
    r' err=(?P<error>\d+)'
    r' nentries=(?P<nentries>\d+)'
    r' text=(?P<text>.*)'
    '$'
)


class Conn(dict):
    def __init__(self, conn=-1, fd=-1):
        self.update({
            'conn': conn,
            'fd': fd,
            'source': 'UNKNOWN',
            'dn': 'UNKNOWN',
            'op': -1,
            'op_type': 'UNKNOWN',
            'op_request': {},
        })


def main(argv):
    conns = {}
    line_n = 0
    for line in sys.stdin:
        line_n += 1
        line = line.rstrip()
        m = re_line.match(line)
        if m is None:
            continue

        conn = int(m.group('conn'))
        chunk = m.group('chunk')
        c = {}

        if m.group('what') == 'fd':
            fd = int(m.group('id'))
            if chunk.startswith('ACCEPT from '):
                c = conns[conn] = Conn(conn=conn, fd=fd)

                chunks = chunk.split(' ')
                if chunks[2].startswith('IP='):
                    c['source'] = chunks[2][3:]
                elif chunks[2].startswith('PATH='):
                    c['source'] = chunks[2][5:]
                else:
                    logger.error(f'Unknown `ACCEPT` line: {line_n}: {line}')
            elif chunk.startswith('closed'):
                try:
                    del(conns[conn])
                except KeyError:
                    pass
                ## FIXME: Show pending op?
            else:
                logger.error(f'Invalid `fd` line: {line_n}: {line}')
                continue
        elif m.group('what') == 'op':
            op = int(m.group('id'))
            if conn not in conns:
                conns[conn] = Conn(conn=conn)
            c = conns[conn]
            if chunk.startswith('RESULT '):
                c['op'] = op
                m = re_result.match(chunk)
                if m is None:
                    logger.error(f'Invalid `RESULT` line: {line_n}: {line}')
                    continue
                c['op_result'] = {
                    'line_n': line_n,
                    'text': m.group('text'),
                }
                error = int(m.group('error'))
                if m.group('tag') is not None:
                    c['op_result']['tag'] = int(m.group('tag'))
                if m.group('oid') is not None:
                    c['op_result']['oid'] = m.group('oid')
                if c['op_type'] == 'BIND' and error == 0:
                    c['dn'] = c['op_request']['dn']
                c['op_result']['error'] = error
            elif chunk.startswith('SEARCH RESULT '):
                c['op'] = op
                m = re_search_result.match(chunk)
                if m is None:
                    logger.error(f'Invalid `SEARCH RESULT` line: {line_n}: {line}')
                    continue
                error = int(m.group('error'))
                c['op_result'] = {
                    'line_n': line_n,
                    'tag': int(m.group('tag')),
                    'nentries': int(m.group('nentries')),
                    'text': m.group('text'),
                    'error': error,
                }
            elif chunk.startswith('BIND '):
                if chunk.find(' method=') > 0:
                    m = re_bind_method.match(chunk)
                    if m is None:
                        logger.error(f'Invalid `BIND method=` line: {line_n}: {line}')
                        continue
                    c['op_type'] = 'BIND'
                    c['op_request'].update({
                        'line_n': line_n,
                        'dn': m.group('dn'),
                        'method': method_by_n[int(m.group('method_n'))],
                    })
                elif chunk.find(' mech=') > 0:
                    m = re_bind_mech.match(chunk)
                    if m is None:
                        logger.error(f'Invalid `BIND mech=` line: {line_n}: {line}')
                        continue
                    if 'dn' in m.groupdict():
                        c['op_request']['dn'] = m.group('dn')
                    else:
                        c['op_request']['dn'] = 'anonymous'
                    c['op_request'].update({
                        'mech': m.group('mech'),
                        'ssf': int(m.group('ssf')),
                    })
                    if 'sasl_ssf' in m.groupdict():
                        c['op_request']['sasl_ssf'] = m.group('sasl_ssf')
                elif chunk.find(' authcid=') > 0:
                    m = re_bind_authcid.match(chunk)
                    if m is None:
                        logger.error(f'Invalid `BIND authcid=` line: {line_n}: {line}')
                        continue
                    c['op_request'].update({
                        'authcid': m.group('authcid'),
                        'authzid': m.group('authzid'),
                    })
                else:
                    logger.error(f'Invalid `BIND` line: {line_n}: {line}')
                    continue
            elif chunk == 'UNBIND':
                c['dn'] = 'UNBOUND'
            elif chunk.startswith('SRCH base='):
                m = re_search_base.match(chunk)
                if m is None:
                    logger.error(f'Invalid `SEARCH base=` line: {line_n}: {line}')
                    continue
                c['op_type'] = 'SEARCH'
                c['op_request'].update({
                    'line_n': line_n,
                    'base': m.group('base'),
                    'scope': scope_by_n.get(int(m.group('scope_n'))),
                    'deref': deref_by_n.get(int(m.group('deref_n'))),
                    'filter': m.group('filter'),
                })
            elif chunk.startswith('SRCH attr='):
                c['op_request'].update({
                    'attrs': chunk[10:].split(' '),
                })
            elif chunk.startswith('ADD dn="'):
                c['op_type'] = 'ADD'
                c['op_request'].update({
                    'dn': chunk[8:-1],
                })
            elif chunk.startswith('DEL dn="'):
                c['op_type'] = 'DELETE'
                c['op_request'].update({
                    'dn': chunk[8:-1],
                })
            elif chunk.startswith('MOD dn='):
                m = re_modify_dn.match(chunk)
                if m is None:
                    logger.error(f'Invalid `MOD dn=` line: {line_n}: {line}')
                    continue
                c['op_type'] = 'MODIFY'
                c['op_request'].update({
                    'line_n': line_n,
                    'dn': m.group('dn'),
                })
            elif chunk.startswith('MOD attr='):
                c['op_request'].update({
                    'attrs': chunk[9:].split(' '),
                })
            elif chunk.startswith('MODRDN dn="'):
                c['op_type'] = 'MODIFYRDN'
                c['op_request'].update({
                    'dn': chunk[11:-1],
                })
            elif chunk.startswith('PASSMOD'):
                c['op_type'] = 'PASSWORD'
                if chunk.startswith('PASSMOD id="'):
                    rq_index = chunk.rfind('"')
                    c['op_request']['dn'] = dn = chunk[12:rq_index]
                    chunk = chunk[rq_index+1:]
                ## New password is supplied
                c['op_request']['new'] = (chunk.find(' new') >= 0)
                ## Old password is supplied
                c['op_request']['old'] = (chunk.find(' old') >= 0)
            elif chunk.startswith('ABANDON msg='): ## FIXME
                pass
            ## FIXME: ADD TLS STARTTLS CANCEL CMP WHOAMI PROXYAUTHZ DENIED EXT
            else:
                logger.error(f'Unknown format: {line_n}: {line}')
        else:
            logger.error(f'Unknown format: {line_n}: {line}')

        if 'op_result' in c:
            c['op_result']['error_text'] = error_text_by_n.get(c['op_result']['error'], 'UNKNOWN')
            print(json.dumps(c, indent=2))
            c['op_request'] = {}
            del(c['op_result'])

    return 0


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
    )

    sys.exit(main(sys.argv[1:]))
