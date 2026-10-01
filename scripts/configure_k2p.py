#!/usr/bin/env python3
"""Apply each option once; retain board, switch, VLAN and wireless definitions."""
import pathlib
import re
import sys

OVERRIDES = {
    'CONFIG_FIRMWARE_ENABLE_USB': 'n',
    'CONFIG_FIRMWARE_ENABLE_IPV6': 'y',
    'CONFIG_FIRMWARE_INCLUDE_CURL': 'y',
    'CONFIG_FIRMWARE_INCLUDE_OPENSSL_EC': 'y',
    'CONFIG_FIRMWARE_INCLUDE_OPENSSL_EXE': 'y',
    'CONFIG_FIRMWARE_INCLUDE_HTTPS': 'y',
    'CONFIG_FIRMWARE_INCLUDE_OPENVPN': 'y',
    'CONFIG_FIRMWARE_INCLUDE_OPENSSH': 'y',
    'CONFIG_FIRMWARE_INCLUDE_DROPBEAR': 'n',
    'CONFIG_FIRMWARE_INCLUDE_SFTP': 'y',
    'CONFIG_FIRMWARE_INCLUDE_WIREGUARD': 'y',
    'CONFIG_FIRMWARE_INCLUDE_SMARTDNS': 'y',
    'CONFIG_FIRMWARE_INCLUDE_VLMCSD': 'n',
    'CONFIG_FIRMWARE_INCLUDE_MINIEAP': 'n',
    'CONFIG_FIRMWARE_INCLUDE_MTR': 'n',
    'CONFIG_FIRMWARE_INCLUDE_SOCAT': 'n',
    'CONFIG_FIRMWARE_INCLUDE_TCPDUMP': 'n',
    'CONFIG_FIRMWARE_INCLUDE_XUPNPD': 'n',
    'CONFIG_FIRMWARE_INCLUDE_SHADOWSOCKS': 'n',
    'CONFIG_FIRMWARE_INCLUDE_SSSERVER': 'n',
    'CONFIG_FIRMWARE_INCLUDE_XRAY': 'n',
    'CONFIG_FIRMWARE_INCLUDE_V2RAY': 'n',
    'CONFIG_FIRMWARE_INCLUDE_TROJAN': 'n',
    'CONFIG_FIRMWARE_INCLUDE_SSOBFS': 'n',
    'CONFIG_FIRMWARE_INCLUDE_ZEROTIER': 'n',
    'CONFIG_FIRMWARE_INCLUDE_ADBYBY': 'n',
    'CONFIG_FIRMWARE_INCLUDE_ADGUARDHOME': 'n',
    'CONFIG_FIRMWARE_INCLUDE_ALIDDNS': 'n',
    'CONFIG_FIRMWARE_INCLUDE_DDNSTO': 'n',
    'CONFIG_FIRMWARE_INCLUDE_ALDRIVER': 'n',
    'CONFIG_FIRMWARE_INCLUDE_SQM': 'n',
    'CONFIG_FIRMWARE_INCLUDE_OC': 'n',
}


def configure(text):
    if not re.search(r'^CONFIG_FIRMWARE_PRODUCT_ID="K2P"$', text, re.M):
        raise ValueError('template is not K2P')
    lines = [line for line in text.splitlines()
             if line.split('=', 1)[0].strip() not in OVERRIDES
             and line != '# K2P 16MB maintenance profile; runtime settings remain in NVRAM.']
    while lines and not lines[-1].strip():
        lines.pop()
    lines += ['', '# K2P 16MB maintenance profile; runtime settings remain in NVRAM.']
    lines += [f'{key}={value}' for key, value in OVERRIDES.items()]
    result = '\n'.join(lines)+'\n'
    keys = re.findall(r'^(CONFIG_\w+)=', result, re.M)
    if len(keys) != len(set(keys)):
        raise ValueError('duplicate configuration assignments')
    return result


if __name__ == '__main__':
    trunk = pathlib.Path(sys.argv[1])
    (trunk / '.config').write_text(configure((trunk / 'configs/templates/K2P.config').read_text()), encoding='utf-8')
