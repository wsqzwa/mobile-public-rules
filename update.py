import csv
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlencode
from urllib.request import urlopen, Request
from concurrent.futures import ThreadPoolExecutor


def fetch(url):
    with urlopen(Request(url, headers={'User-Agent': 'Mozilla/5.0 (public rules updater)'}), timeout=180) as response:
        return response.read().decode('utf-8-sig')


def ooni():
    today = datetime.now(timezone.utc).date()
    query = urlencode(dict(probe_cc='CN', test_name='web_connectivity', since=today-timedelta(days=90), until=today, axis_x='domain', format='CSV'))
    rows = csv.DictReader(fetch('https://api.ooni.io/api/v1/aggregation?' + query).splitlines())
    if not {'domain','confirmed_count'}.issubset(rows.fieldnames or []):
        raise ValueError('unexpected CSV')
    hosts = set()
    for row in rows:
        host = row['domain'].strip().lower()
        if int(row['confirmed_count']) > 0 and len(host) <= 253 and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z][a-z0-9-]*', host):
            hosts.add(host)
    return hosts


def greatfire():
    def page(offset):
        return json.loads(fetch('https://en.greatfire.org/api/tags?status=blocked&limit=200&offset=' + str(offset)))
    first = page(0)
    total, step, stamp = first['total'], first['limit'], first['generated_at']
    if not first['available'] or total < 1 or step != 200:
        raise ValueError('invalid snapshot')
    lines = set()
    seen = 0
    def add(result, offset):
        nonlocal seen
        rows = result['items']
        if result['generated_at'] != stamp or result['total'] != total or result['offset'] != offset or len(rows) != min(step,total-offset):
            raise ValueError('incomplete snapshot')
        for row in rows:
            if row['status'] != 'blocked':
                raise ValueError('unexpected verdict')
            seen += 1
            try:
                u = urlsplit(row['url']); host = (u.hostname or '').lower().rstrip('.')
                if u.scheme not in ('http','https','ftp') or not host: continue
                port = u.port if u.port is not None else {'http':80,'https':443,'ftp':21}[u.scheme]
                if not 1 <= port <= 65535: continue
            except ValueError:
                continue
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                if re.fullmatch('[a-z0-9._-]+',host) and not re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+',host):
                    lines.add('DOMAIN,'+host)
                continue
            family = '6' if ip.version == 6 else ''
            lines.add(f'AND,((NETWORK,TCP),(DST-PORT,{port}),(OR,((DOMAIN-REGEX,^$),(DOMAIN-REGEX,^[0-9a-fA-F:.]+$))),(IP-CIDR{family},{ip}/{ip.max_prefixlen},no-resolve))')
    add(first, 0)
    offsets = range(step,total,step)
    with ThreadPoolExecutor(max_workers=4) as pool:
        for offset,result in zip(offsets,pool.map(page,offsets)):
            add(result,offset)
    if seen != total: raise ValueError('partial snapshot')
    return lines


sources = {'ooni':(ooni,'ooni-cn-confirmed.txt'), 'greatfire':(greatfire,'greatfire-blocked-web.txt')}
if __name__ == '__main__':
    generator, name = sources[sys.argv[1]]
    rules = generator()
    if not rules: raise ValueError('empty result')
    Path(name).write_text(chr(10).join(sorted(rules))+chr(10), encoding='utf-8')
    print(f'{name}: {len(rules)} rules')
