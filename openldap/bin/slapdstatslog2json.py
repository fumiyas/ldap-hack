#!/usr/bin/env python3
## -*- coding: utf-8 -*- vim:shiftwidth=4:expandtab:
##
## OpenLDAP: Annotate and Convert slapd stats log to JSON
##
## SPDX-FileCopyrightText: 2020-2025 SATOH Fumiyasu @ OSSTech Corp., Japan
## SPDX-License-Identifier: GPL-3.0-or-later
##

import logging
import sys
import re
import datetime
import json
import calendar
import itertools

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(name)s: %(levelname)s: %(message)s',
    )
    logger = logging.getLogger(sys.argv[0])
else:
    logger = logging.getLogger(__name__)

month_by_abbr = {abbr: index for index, abbr in enumerate(calendar.month_abbr) if abbr}

bind_method_by_n = {
    0x00: 'None',
    0x80: 'Simple',
    0xA3: 'SASL',
}
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
    ## Other errors
    0x4C: 'VLV_ERROR',
    0x50: 'OTHER',
    ## LCUP operation (not implemented in OpenLDAP)
    0x71: 'CUP_RESOURCES_EXHAUSTED',
    0x72: 'CUP_SECURITY_VIOLATION',
    0x73: 'CUP_INVALID_DATA',
    0x74: 'CUP_UNSUPPORTED_SCHEME',
    0x75: 'CUP_RELOAD_REQUIRED',
    ## Cancel operation
    0x76: 'CANCELLED',
    0x77: 'NO_SUCH_OPERATION',
    0x78: 'TOO_LATE',
    0x79: 'CANNOT_CANCEL',
    ## Assertion control
    0x7A: 'ASSERTION_FAILED',
    ## Proxied Authorization Denied
    0x7B: 'PROXIED_AUTHORIZATION_DENIED',

    ## Experimental result codes
    ## LDAP Sync
    0x1000: 'SYNC_REFRESH_REQUIRED',

    ## Private Use result codes
    0x4100: 'X_SYNC_REFRESH_REQUIRED',  # defunct
    0x410f: 'X_ASSERTION_FAILED',       # defunct
    ## LDAP No-Op control
    0x410e: 'X_NO_OPERATION',
    ## Chaining Behavior control
    0x4110: 'X_NO_REFERRALS_FOUND',
    0x4111: 'X_CANNOT_CHAIN',
    ## Distributed Procedures
    0x4112: 'X_INVALIDREFERENCE',
    ## LDAP Transaction
    0x4120: 'X_TXN_SPECIFY_OKAY',
    0x4121: 'X_TXN_ID_INVALID',
}

re_stats_line = re.compile(
    r'('
    r'(?P<month_abbr>[A-Z][a-z][a-z])'
    r' (?P<month_day>[ 0-3][0-9])'
    r' (?P<time>(?P<hour>[0-2][0-9]):(?P<minute>[0-5][0-9]):(?P<second>[0-6][0-9]))'
    r'|'
    r'(?P<datetime>[0-9]{4}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-6][0-9]\.[0-9]+[-+][01][0-9]:[0-9][0-9])'
    r')'
    r' (?P<hostname>[\w\-.]+)'
    r' [\w\-]+\[(?P<pid>[0-9]+)\]:'
    r' conn=(?P<conn_id>[0-9]+)'
    r' (?P<what>fd|op)=(?P<id>[0-9]+)'
    r' (?P<chunk>.*)'
    '$'
)

re_bind_method = re.compile(
    r'BIND'
    r' dn="(?P<dn>[^"]*)"'
    r' method=(?P<method_n>[0-9]+)'
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
    r' mech=(?P<mech>[\w\-]+)'
    r'( (bind|sasl)_ssf=(?P<bind_ssf>[0-9]+))?'
    r' ssf=(?P<ssf>[0-9]+)'
    '$'
)

re_whoami = re.compile(
    r'WHOAMI'
    '$'
)

re_search_base = re.compile(
    r'SRCH'
    r' base="(?P<base>[^"]*)"'
    r' scope=(?P<scope_n>[0-9]+)'
    r' deref=(?P<deref_n>[0-9]+)'
    r' filter="(?P<filter>.*)"'
    '$'
)

re_cmp = re.compile(
    r'CMP'
    r' dn="(?P<dn>[^"]*)"'
    r' attr="(?P<attr>[^"]*)"'
    '$'
)

re_modify_dn = re.compile(
    r'MOD'
    r' dn="(?P<dn>[^"]*)"'
    '$'
)

re_result = re.compile(
    r'RESULT'
    r'( tag=(?P<tag>[0-9]+))?'
    r'( oid=(?P<oid>\W*))?'
    r' err=(?P<error>[0-9]+)'
    r'( qtime=(?P<qtime>[0-9]+\.[0-9]+))?'
    r'( etime=(?P<etime>[0-9]+\.[0-9]+))?'
    r' text=(?P<text>.*)'
    '$'
)
re_search_result = re.compile(
    r'SEARCH RESULT'
    r' tag=(?P<tag>[0-9]+)'
    r' err=(?P<error>[0-9]+)'
    r'( qtime=(?P<qtime>[0-9]+\.[0-9]+))?'
    r'( etime=(?P<etime>[0-9]+\.[0-9]+))?'
    r' nentries=(?P<nentries>[0-9]+)'
    r' text=(?P<text>.*)'
    '$'
)


class Connection():
    def __init__(self, conn_id):
        self.line_n = None
        self.datetime = None
        self.op_by_id = {}
        self.info = {
            'conn': conn_id,
            'fd': None,
            'source': None,
            'tls': None,
            'dn': None,
        }

    @property
    def id(self):
        return self.info['conn']

    @id.setter
    def id(self, id):
        self.info['conn'] = id

    @property
    def fd(self):
        return self.info['fd']

    @fd.setter
    def fd(self, fd):
        self.info['fd'] = fd

    @property
    def tls(self):
        return self.info['tls']

    @tls.setter
    def tls(self, tls_p):
        self.info['tls'] = tls_p

    @property
    def source(self):
        return self.info['source']

    @source.setter
    def source(self, source):
        self.info['source'] = source

    @property
    def dn(self):
        return self.info['dn']

    @dn.setter
    def dn(self, dn):
        self.info['dn'] = dn

    def unbind(self):
        self.info['dn_unbound'] = self.info['dn']
        self.dn = 'UNBOUND'

    def get_op_by_id(self, op_id):
        if op_id not in self.op_by_id:
            self.op_by_id[op_id] = Operation(conn=self, op_id=op_id)

        return self.op_by_id[op_id]

    def remove_op(self, op):
        try:
            del self.op_by_id[op.id]
        except KeyError:
            pass


class Operation():
    def __init__(self, conn, op_id=None):
        self.conn = conn
        self.id = op_id
        self.type = None
        self.request_datetime = None
        self.request = {
            'line_n': None,
            'timestamp': None,
        }
        self.result_datetime = None
        self.result = {
            'line_n': None,
            'timestamp': None,
            'error': None,
            'error_text': None,
        }

    def to_json(self):
        if 'etime' not in self.result:  # OpenLDAP 2.4
            if self.request_datetime is None:
                self.result['etime'] = None
            else:
                self.result['etime'] = (self.result_datetime - self.request_datetime).total_seconds()

        return json.dumps({
            **self.conn.info,
            'op': self.id,
            'op_type': self.type,
            'op_request': self.request,
            'op_result': self.result,
        })

    def set_request(self, op_type):
        self.type = op_type
        self.request_datetime = self.conn.datetime
        self.request['line_n'] = self.conn.line_n
        self.request['timestamp'] = self.request_datetime.isoformat()

    def set_result(self, error, result=None):
        self.result_datetime = self.conn.datetime
        self.result['line_n'] = self.conn.line_n
        self.result['timestamp'] = self.result_datetime.isoformat()
        self.result['error'] = error
        self.result['error_text'] = error_text_by_n.get(error, 'UNKNOWN')
        if result is not None:
            self.result.update(result)


def main(argv):
    line_n = 0

    ## Guess log year (standard syslog has no year in timestamp)
    for firstline in sys.stdin:
        m = re_stats_line.match(firstline)
        if m is None:
            line_n += 1
            continue

        if m.group('datetime'):
            ## ISO 8601 date and time format
            break

        ## Legacy syslog date and time format (no year)
        dt_now = datetime.datetime.now()
        year = dt_now.year
        month = month_by_abbr[m.group('month_abbr')]
        mday = int(m.group('month_day'))
        hour = int(m.group('hour'))
        minute = int(m.group('minute'))
        second = int(m.group('second'))
        dt = datetime.datetime(year, month, mday, hour, minute, second, 0)
        if dt > dt_now:
            year = year - 1
        break
    else:
        ## No stats log
        return 0

    conn_by_conn_id = {}
    for line in itertools.chain([firstline], sys.stdin):
        line_n += 1
        line = line.rstrip()
        m = re_stats_line.match(line)
        if m is None:
            continue

        conn_id = int(m.group('conn_id'))
        if conn_id not in conn_by_conn_id:
            conn_by_conn_id[conn_id] = Connection(conn_id=conn_id)
        conn = conn_by_conn_id[conn_id]
        conn.line_n = line_n

        if m.group('datetime'):
            ## ISO 8601 date and time format
            conn.datetime = datetime.datetime.fromisoformat(m.group('datetime'))
        else:
            ## Legacy syslog date and time format (no year)
            month = month_by_abbr[m.group('month_abbr')]
            mday = int(m.group('month_day'))
            hour = int(m.group('hour'))
            minute = int(m.group('minute'))
            second = int(m.group('second'))
            conn.datetime = datetime.datetime(year, month, mday, hour, minute, second, 0)

        chunk = m.group('chunk')
        if m.group('what') == 'fd':
            fd = int(m.group('id'))
            op = Operation(conn=conn)

            if chunk.startswith('ACCEPT from '):
                op.set_request('CONNECT')
                ## FIXME: Check if conn_id is already exists
                conn.fd = fd
                conn.dn = 'ANONYMOUS'

                chunks = chunk.split(' ')
                if chunks[2].startswith('IP='):
                    conn.source = chunks[2][3:]
                elif chunks[2].startswith('PATH='):
                    conn.source = chunks[2][5:]
                else:
                    logger.error(f'Unknown `ACCEPT` line: {line_n}: {line}')
                    conn.source = 'UNKNOWN'
                op.set_result(error=0)
            elif chunk.startswith('TLS '):
                conn.tls = True
                continue
            elif chunk.startswith('closed'):
                op.set_request('DISCONNECT')
                result = {}
                try:
                    result['text'] = chunk[chunk.index('(') + 1:-1]
                except ValueError:
                    pass
                op.set_result(error=0, result=result)
                try:
                    del conn_by_conn_id[conn_id]
                except KeyError:
                    pass

                ## FIXME: Print pending operation(s)?
                #if conn.op_by_id:
                #    conn.info['op_pending'] conn.op_by_id.keys()
            else:
                logger.error(f'Invalid `fd` line: {line_n}: {line}')
                continue

            print(op.to_json())
            conn.remove_op(op)

        elif m.group('what') == 'op':
            op_id = int(m.group('id'))

            if chunk.startswith('RESULT '):
                op = conn.get_op_by_id(op_id)
                m = re_result.match(chunk)
                if m is None:
                    logger.error(f'Invalid `RESULT` line: {line_n}: {line}')
                    continue
                error = int(m.group('error'))
                result = {
                    'text': m.group('text'),
                }
                if m.group('tag') is not None:
                    result['tag'] = int(m.group('tag'))
                if m.group('oid') is not None:
                    result['oid'] = m.group('oid')
                if m.group('qtime') is not None:
                    result['qtime'] = float(m.group('qtime'))
                if m.group('etime') is not None:
                    result['etime'] = float(m.group('etime'))
                op.set_result(error=error, result=result)
                print(op.to_json())
                conn.remove_op(op)

                if op.type == 'BIND' and error == 0:
                    conn.dn = op.request['dn']
                elif op.type == 'STARTTLS' and error == 0:
                    conn.tls = True

                continue

            if chunk.startswith('SEARCH RESULT '):
                op = conn.get_op_by_id(op_id)
                m = re_search_result.match(chunk)
                if m is None:
                    logger.error(f'Invalid `SEARCH RESULT` line: {line_n}: {line}')
                    continue
                error = int(m.group('error'))
                result = {
                    'nentries': int(m.group('nentries')),
                    'tag': int(m.group('tag')),
                    'text': m.group('text'),
                }
                if m.group('qtime') is not None:
                    result['qtime'] = float(m.group('qtime'))
                if m.group('etime') is not None:
                    result['etime'] = float(m.group('etime'))
                op.set_result(error=error, result=result)
                print(op.to_json())
                conn.remove_op(op)
                continue

            if chunk == 'UNBIND':
                op = conn.get_op_by_id(op_id)
                op.set_request('UNBIND')
                op.set_result(error=0)
                print(op.to_json())
                conn.remove_op(op)
                conn.unbind()
                continue

            op = conn.get_op_by_id(op_id)

            if chunk == 'STARTTLS':
                op.set_request('STARTTLS')

            elif chunk.startswith('BIND '):
                op.set_request('BIND')
                if chunk.find(' method=') > 0:
                    m = re_bind_method.match(chunk)
                    if m is None:
                        logger.error(f'Invalid `BIND method=` line: {line_n}: {line}')
                        continue
                    op.request['dn'] = m.group('dn')
                    op.request['method'] = bind_method_by_n[int(m.group('method_n'))]
                elif chunk.find(' mech=') > 0:
                    m = re_bind_mech.match(chunk)
                    if m is None:
                        logger.error(f'Invalid `BIND mech=` line: {line_n}: {line}')
                        continue
                    if 'dn' in m.groupdict():
                        op.request['dn'] = m.group('dn')
                    else:
                        op.request['dn'] = 'ANONYMOUS'
                    op.request['mech'] = m.group('mech')
                    op.request['ssf'] = int(m.group('ssf'))
                    if 'bind_ssf' in m.groupdict():
                        op.request['bind_ssf'] = int(m.group('bind_ssf'))
                elif chunk.find(' authcid=') > 0:
                    m = re_bind_authcid.match(chunk)
                    if m is None:
                        logger.error(f'Invalid `BIND authcid=` line: {line_n}: {line}')
                        continue
                    op.request['authcid'] = m.group('authcid')
                    op.request['authzid'] = m.group('authzid')
                else:
                    logger.error(f'Invalid `BIND` line: {line_n}: {line}')
                    continue

            elif chunk.startswith('WHOAMI'):
                op.set_request('WHOAMI')

                m = re_whoami.match(chunk)
                if m is None:
                    logger.error(f'Invalid `WHOAMI` line: {line_n}: {line}')
                    continue

            elif chunk.startswith('SRCH base='):
                op.set_request('SEARCH')

                m = re_search_base.match(chunk)
                if m is None:
                    logger.error(f'Invalid `SEARCH base=` line: {line_n}: {line}')
                    continue

                op.request['base'] = m.group('base')
                op.request['scope'] = scope_by_n.get(int(m.group('scope_n')))
                op.request['deref'] = deref_by_n.get(int(m.group('deref_n')))
                op.request['filter'] = m.group('filter')

            elif chunk.startswith('SRCH attr='):
                op.request['attrs'] = chunk[10:].split(' ')

            elif chunk.startswith('CMP '):
                op.set_request('COMPARE')

                op.request['attrs'] = chunk[10:].split(' ')
                m = re_cmp.match(chunk)
                if m is None:
                    logger.error(f'Invalid `CMP` line: {line_n}: {line}')
                    continue
                op.request['dn'] = m.group('dn')
                op.request['attr'] = m.group('attr')

            elif chunk.startswith('ADD dn="'):
                op.set_request('ADD')
                op.request['dn'] = chunk[8:-1]

            elif chunk.startswith('DEL dn="'):
                op.set_request('DELETE')
                op.request['dn'] = chunk[8:-1]

            elif chunk.startswith('MOD dn='):
                op.set_request('MODIFY')

                m = re_modify_dn.match(chunk)
                if m is None:
                    logger.error(f'Invalid `MOD dn=` line: {line_n}: {line}')
                    continue
                op.request['dn'] = m.group('dn')

            elif chunk.startswith('MOD attr='):
                op.request['attrs'] = chunk[9:].split(' ')

            elif chunk.startswith('MODRDN dn="'):
                op.set_request('MODIFYRDN')
                op.request['dn'] = chunk[11:-1]

            elif chunk.startswith('PASSMOD'):
                op.set_request('PASSWORD')
                request = op.request
                if chunk.startswith('PASSMOD id="'):
                    rq_index = chunk.rfind('"')
                    request['dn'] = chunk[12:rq_index]
                    chunk = chunk[rq_index + 1:]
                ## New password is supplied
                request['new'] = (chunk.find(' new') >= 0)
                ## Old password is supplied
                request['old'] = (chunk.find(' old') >= 0)

            elif chunk.startswith('EXT '):  # FIXME: conn=100931 op=0 EXT oid=...
                continue
            elif chunk.startswith('ABANDON msg='):  # FIXME
                continue

            ## FIXME: Support CANCEL WHOAMI PROXYAUTHZ DENIED

            else:
                logger.error(f'Unknown line: {line_n}: {line}')

        else:
            logger.error(f'Unknown line: {line_n}: {line}')

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
