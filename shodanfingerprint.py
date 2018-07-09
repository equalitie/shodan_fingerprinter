import shodan
import argparse
import os
import sys
import re
import time
from dateutil.parser import parse
from datetime import datetime, timedelta


FINGERPRINT = [
        {'name': 'MikroTik', 'filter': 'tcp/2000', 'test': 'contains', 'contains': ['product', 'MikroTik'], 'result': {'type': 'Router', 'device': 'MikroTik Router', 'os': 'RouterOS'}},
        {'name': 'HikVision DVR DNVRS-Webs web server', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['data', 'Server: DNVRS-Webs'], 'result': {'type': 'Camera', 'device': 'HikVision DVR device', 'os': 'Unknown'}, 'ref': 'https://www.mdsec.co.uk/2016/10/building-an-iot-botnet-bsides-manchester-2016/'},
        {'name': 'HikVision DVR DVRDVS-Webs web server', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['data', 'Server: DVRDVS-Webs'], 'result': {'type': 'Camera', 'device': 'HikVision DVR device'}, 'ref': 'https://www.mdsec.co.uk/2016/10/building-an-iot-botnet-bsides-manchester-2016/'},
        {'name': 'Technicolor SNMP', 'filter': 'udp/161', 'test': 'contains', 'contains': ['data', 'Technicolor'], 'result': {'type': 'Router', 'device': 'Technicolor'}},
        {'name': 'TPLink web admin interface', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['data', 'TD854W'], 'result': {'type': 'Router', 'device': 'TPLink TD854W'}},
        {'name': 'ASUS RT-AC3100 FTP banner', 'filter': 'tcp/21', 'test': 'contains', 'contains': ['data', 'ASUS RT-AC3100'], 'result': {'type': 'Router', 'device': ' ASUS RT-AC3100'}},
        {'name': 'Thomson CableHome Gateway SNMP', 'filter': 'udp/161', 'test': 'contains', 'contains': ['data', 'Thomson CableHome Gateway'], 'result': {'type': 'Router', 'device': 'Thomson CableHome Gateway'}},
        {'name': 'Technicolor admin page', 'filter': 'tcp/80', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['html', 'Technicolor - M\u00f3dem'], 'result': {'type': 'Router', 'device': 'Technicolor Model'}},
        {'name': 'D-LINK admin page', 'filter': 'tcp/8181', 'test': 'contains', 'contains': ['data', '<title>D-LINK</title>'], 'result': {'type': 'Router', 'device': 'D-LINK router'}},
        {'name': 'IgdAuthentication realm', 'filter': 'tcp/7547', 'test': 'contains', 'contains': ['data', 'Digest realm="IgdAuthentication"'], 'result': {'type': 'Router', 'device': 'unknown'}},
        {'name': 'D-LINK UPNP uuid', 'filter': 'udp/1900', 'test': 'regex', 'regex': '\/dyndev\/uuid\:\w+-\w+-\w+-\w+-1cbdb9\w+', 'result': {'type': 'Router', 'device': 'D-LINK'}},
        {'name': 'ZTE UPNP uuid', 'filter': 'udp/1900', 'test': 'regex', 'regex': '\/dyndev\/uuid\:\w+-\w+-\w+-\w+-002293\w+', 'result': {'type': 'Router', 'device': 'ZTE Router'}},
        {'name': 'Linksys Router admin page header', 'filter': 'tcp/8080', 'test': 'contains', 'contains': ['html', '# Copyright (C) 2009, CyberTAN Corporation\r\n# All Rights Reserved.'], 'result': {'type': 'Router', 'device': 'Linksys'}},
        {'name': 'Linksys Router admin page header', 'filter': 'tcp/8081', 'test': 'contains', 'contains': ['html', '# Copyright (C) 2009, CyberTAN Corporation\r\n# All Rights Reserved.'], 'result': {'type': 'Router', 'device': 'Linksys'}},
        {'name': 'Cisco iOS admin interface', 'filter': 'tcp/8080', 'test': 'contains', 'contains': ['data', 'Server: cisco-IOS'], 'result': {'type': 'Router', 'device': 'Cisco iOS Router'}},
        {'name': 'DrayTek Vigor ADSL router sshd', 'filter': 'tcp/22', 'test': 'contains', 'contains': ['data', 'SSH-2.0-DraySSH_2.0'], 'result': {'type': 'Router', 'device': 'DrayTek Vigor ADSL router sshd'}},
        {'name': 'AirOS Set Cookie admin age', 'filter': 'tcp/443', 'test': 'contains', 'contains': ['data', 'Set-Cookie: AIROS_'], 'result': {'type': 'Router', 'device': 'AirOS router'}},
        {'name': 'Hikvision HTTP Authentication', 'filter': 'tcp/554', 'test': 'contains', 'contains': ['data', 'Digest realm=\"Hikvision\"'], 'result': {'type': 'Router', 'device': 'HikVision DVR device'}},
        {'name': 'Dahua RTSP authentication', 'filter': 'tcp/554', 'test': 'contains', 'contains': ['data', 'Basic realm=\"DahuaRtsp\"'], 'result': {'type': 'Camera', 'device': 'Dahua DVR Camera'}},
        {'name': 'Huawei Home gateway AuthRealm', 'filter': 'tcp/7547', 'test':'contains', 'contains': ['data', 'Digest realm=\"HuaweiHomeGateway\"'], 'result': {'type': 'Router', 'device': 'Huawei Home Gateway'}},
        {'name': 'Realtek Gateway Auth realm', 'filter': 'tcp/7547', 'test': 'contains', 'contains': ['data', 'Digest realm=\"realtek.com'], 'result': {'type': 'Router', 'device': 'RealTek Router'}},
        {'name': 'Realtek UPnP', 'filter': 'udp/1900', 'test': 'contains', 'contains': ['data', 'OS 1.0 UPnP/1.0 Realtek/'], 'result': {'type': 'Router', 'device': 'RealTek Router'}},
        {'name': 'TPLink Wireless TL-WR720N Basic Realm', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['data', '150Mbps Wireless N Router TL-WR720N'], 'result': {'type': 'Router', 'device': 'TPLink TL-WR720N Wireless Router'}},
        {'name': 'Apache Fedora', 'filter': 'tcp/80', 'test': 'regex', 'regex': 'Apache\/\d+\.\d+\.\d+ \(Fedora\)', 'result': {'type': 'Server', 'device': 'Fedora Server'}},
        {'name': 'RTSP H264DVR Server', 'filter': 'tcp/554', 'test': 'contains', 'contains': ['data', 'Server: H264DVR'], 'result': {'type': 'Camera', 'device': 'H.264 DVR'}},
        {'name': 'ZTE Router Digest realm', 'filter': 'tcp/7547', 'test': 'contains', 'contains': ['data', 'Digest realm=\"cpe@zte.com\"'], 'result': {'type': 'Router', 'device': 'ZTE Router'}},
        {'name': 'Huawei Wifi Router cert', 'filter': 'tcp/443', 'test': 'contains', 'contains': ['ssl.cert.subject.emailAddress', 'mobile.wifi@huawei.com'], 'result': {'type': 'Router', 'device': 'Huawei Wifi Router'}},
        {'name': 'D-LINK admin page', 'filter': 'tcp/8080', 'test': 'contains', 'contains': ['html', '<title>D-LINK SYSTEMS, INC. | WIRELESS ROUTER </title>'], 'result': {'type': 'Router', 'device': 'D-LINK Wireless router'}},
        {'name': 'MikroTik SNMP info', 'filter': 'udp/161', 'test': 'contains', 'contains': ['data', 'RouterOS'], 'result': {'type': 'Router', 'device': 'MikroTik Router'}},
        {'name': 'Dahua DVR certificate', 'filter': 'tcp/443', 'test': 'contains', 'contains': ['ssl.cert.issuer.O', 'DahuaTech'], 'result': {'type': 'Camera', 'device': 'Dahua DVR'}},
        {'name': 'Daytek Vigor admin page', 'filter': 'tcp/8080', 'test': 'contains', 'contains': ['http.title', 'Vigor Login Page'], 'result': {'type': 'Router', 'device': 'Daytek Vigor Router'}},
        {'name': 'MikroTik telnet server', 'filter': 'tcp/23', 'test': 'contains', 'contains': ['data', 'MikroTik'], 'result': {'type': 'Router', 'device': 'MikroTik Router'}},
        {'name': 'MS IIS header', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['data', 'Microsoft IIS httpd'], 'result': {'type': 'Server', 'device': 'Windows Server', 'os': 'Windows'}},
        {'name': 'MS IIS header', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['data', 'Server: Microsoft-IIS/'], 'result': {'type': 'Server', 'device': 'Windows Server', 'os': 'Windows'}},
        {'name': 'MS IIS header port 8080', 'filter': 'tcp/8080', 'test': 'contains', 'contains': ['data', 'Server: Microsoft-IIS/'], 'result': {'type': 'Server', 'device': 'Windows Server', 'os': 'Windows'}},
        {'name': 'SMB Windows Server 2008', 'filter': 'tcp/445', 'test': 'contains', 'contains': ['smb.os', 'Windows Server 2008'], 'result': {'type': 'Server', 'device': 'Windows Server 2008'}},
        {'name': '4ipnet WHG325 admin page', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['http.title', 'WHG325'], 'result': {'type': 'Router', 'device': '4ipnet WHG325 Router'}, 'ref': 'http://www.4ipnet.com/products/wlan-gateway-controller/WHG325'},
        {'name': 'MikroTik FTP server', 'filter': 'tcp/21', 'test': 'contains', 'contains': ['data', 'FTP server (MikroTik'], 'result': {'type': 'Router', 'device': 'MikroTik Router', 'os': 'RouterOS'}},
        {'name': 'AVIO CCTV system', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['html', 'window.location=\"https://\" + SSLHostIp + \":\" + SSLPort;'], 'result':{'type': 'Camera', 'device': 'AVIO CCTV DVR system'}},
        {'name': 'Grace Communications PPTP info', 'filter': 'tcp/1723', 'test': 'contains', 'contains': ['data', 'Hostname: Grace Broadband'], 'result': {'type': 'Router', 'device': 'Grace Communications Wireless Router'}},
        {'name': 'MikroTik PPTP server', 'filter': 'tcp/1723', 'test': 'contains', 'contains': ['data', 'Hostname: MikroTik'], 'result': {'type': 'Router', 'device': 'MikroTik Router', 'os': 'RouterOS'}},
        {'name': 'Innacomm W3400V6 ADSL Router SNMP header', 'filter': 'udp/161', 'test': 'contains', 'contains': ['data', 'W3400V6'], 'result': {'type': 'Router', 'device': 'Innacomm W3400V6 ADSL Router'}},
        {'name': 'Tenda D301 Router admin page', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['html', '<title>D301</title>'], 'result': {'type': 'Router', 'device': 'Tenda D301 Router'}, 'ref': 'http://www.tendacn.com/en/product/d301.html'},
        {'name': 'TP-LINK WR840N Basic realm', 'filter': 'tcp/8080', 'test': 'contains', 'contains': ['data', 'TP-LINK Wireless N Router WR840N'], 'result': {'type': 'Router', 'device': 'TP-LINK Wireless N Router WR840N'}},
        {'name': 'Tenda 11N Wireless Router Login Screen', 'filter': 'tcp/8080', 'test': 'contains', 'contains': ['html', '<title>Tenda 11N Wireless Router Login Screen</title>'], 'result': {'type': 'Router', 'device': 'Tenda 11N Wireless Router'}},
        {'name': 'Hikvision web server', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['data', 'Server: Hikvision-Webs'], 'result': {'type': 'Camera', 'device': 'Hikvision DVR system'}},
        {'name': 'Synology NAS admin page', 'filter': 'tcp/5001', 'test': 'contains', 'contains': ['html', '<meta name="description" content="DiskStation provides a full-featured network attached storage (NAS) solution to help you manage, backup and share data among Windows, Mac and Linux easily." />'], 'result': {'type': 'NAS', 'device': 'Synology DiskStation'}},
        {'name': 'Huawei EchoLife HG520 Home Gateway', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['data', 'EchoLife Home Gateway'], 'result': {'type': 'Router', 'device': 'Huawei EchoLife Router'}},
        {'name': 'Linksys Smart Wi-Fi admin page', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['html', '<title>Linksys Smart Wi-Fi</title>'], 'result': {'type': 'Router', 'device': 'Linksys router'}},
        {'name': 'FRITZ!Box admin page', 'filter': 'tcp/443', 'test': 'contains', 'contains': ['html', '"pageTitle":"Welcome to your FRITZ!Box"'], 'result': {'type': 'Router', 'device': 'Fritz!Box ADSL Router'}, 'ref': 'https://en.wikipedia.org/wiki/Fritz!Box'},
        {'name': 'Huawei HG8247H admin page', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['html', "var ProductName = 'HG8247H';"], 'result': {'type': 'Router', 'device': 'Huawei HG8247H'}},
        {'name': 'TP-LINK TD-W8901G SNMP', 'filter': 'udp/25033', 'test': 'contains', 'contains': ['data', 'TD-W8901G'], 'result': {'type': 'Router', 'device': 'TP-Link TD-W8901G Router'}},
        {'name': 'Hikvision admin panel', 'filter': 'tcp/8080', 'test': 'contains', 'contains': ['html', 'window.location.href = \"/doc/page/login.asp?_\" + (new Date()).getTime();'], 'result': {'type': 'Camera', 'device': 'Hikvision DVR system'}},
        {'name': 'Microsoft ESMTP Mail service', 'filter': 'tcp/587', 'test': 'contains', 'contains': ['data', 'Microsoft ESMTP MAIL Service'], 'result': {'type': 'Server', 'device': 'Windows Server', 'os': 'Windows'}},
        {'name': 'Cisco Router admin panel', 'filter': 'tcp/443', 'test': 'contains', 'contains': ['ssl.cert.issuer.CN', 'Cisco'], 'result': {'type': 'Router', 'device': 'Cisco router'}},
        {'name': 'Multitech admin panel certificate', 'filter': 'tcp/443', 'test': 'contains', 'contains': ['ssl.cert.subject.O', 'Multitech'], 'result': {'type': 'Router', 'device': 'Multitech Router'}},
        {'name': 'SAGEMBOX NetBIOS servername', 'filter': 'udp/137', 'test': 'contains', 'contains': ['data', 'NetBIOS Response\nServername: SAGEMBOX'], 'result': {'type': 'Router', 'device': 'SAGEMBOX Routers'}, 'ref': 'https://forum.hardware.fr/hfr/HardwarePeripheriques/Divers/sagembox-twonkymedia-sujet_49647_1.htm'},
        {'name': 'Huawei ssh server', 'filter': 'tcp/22', 'test': 'regex', 'regex': 'SSH-\d+\.\d+-HUAWEI-', 'result': {'type': 'Router', 'device': 'Huawei router'}},
        {'name': 'Fortinet router certificate', 'filter': 'tcp/443', 'test': 'contains', 'contains': ['ssl.cert.issuer.emailAddress', 'support@fortinet.com'], 'result': {'type': 'Router', 'device': 'Fortinet router'}},
        {'name': 'D-LINK Samba server', 'filter': 'tcp/445', 'test': 'contains', 'contains': ['data', '(DIR850L Samba Server)'], 'result': {'type': 'Router', 'device': 'D-LINK DIR-850L wireless cloud router'}},
        {'name': 'Skyworth model SNMP banner', 'filter': 'udp/161', 'test': 'contains', 'contains': ['data', 'Skyworth'], 'result': {'type': 'Router', 'device': 'Skyworth Wireless cable model'}},
        {'name': 'Ubiquiti AirRouter udp 10001', 'filter': 'udp/10001', 'test': 'contains', 'contains': ['data', 'Ubiquiti Networks Device'], 'result': {'type': 'Router', 'device': 'Ubiquiti AirRouter', 'os': 'airOS'}},
        {'name': 'Mikrotik RouterOS configuration page', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['http.title', 'RouterOS router configuration page'], 'result': {'type': 'Router', 'os': 'RouterOS', 'device': 'Mikrotik Router'}},
        {'name': 'Mikrotik HTTP Proxy', 'filter': 'tcp/8080', 'test': 'contains', 'contains': ['html', '(Mikrotik HttpProxy)'], 'result': {'type': 'Router', 'device': 'Mikrotik Router'}},
        {'name': 'Huawei HG8245 login page', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['html', 'var LoginTimes = 0;\r\n\r\nvar ProductName = \'HG8245\';'], 'result': {'type': 'Router', 'device': 'Huawei HG8245 Router'}},
        {'name': 'SERCOMM authentication realm', 'filter': 'tcp/8081', 'test': 'contains', 'contains': ['data', 'SERCOMM CPE Authentication'], 'result': {'type': 'Router', 'device': 'SerComm router'}},
        {'name': 'Ubiquiti N5D-16M', 'filter': 'udp/10000', 'test': 'contains', 'contains': ['data', 'Product: N5B-16'], 'result': {'type': 'Router', 'device': 'Ubiquiti N5B-16 Airmax router'}},
        {'name': 'Windows RDP Server', 'filter': 'tcp/3389', 'test': 'contains', 'contains': ['data', 'Remote Desktop Protocol'], 'result': {'type': 'Server', 'device': 'Windows Server', 'os': 'Windows'}},
        {'name': 'Tor Exit Router HTTP header', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['data', 'X-Your-Address-Is:'], 'result': {'type': 'Server', 'device': 'Tor router'}},
        {'name': 'Tor Exit Router HTTP header', 'filter': 'tcp/444', 'test': 'contains', 'contains': ['data', 'X-Your-Address-Is:'], 'result': {'type': 'Server', 'device': 'Tor router'}},
        {'name': 'Tor Exit Router HTTP header', 'filter': 'tcp/8080', 'test': 'contains', 'contains': ['data', 'X-Your-Address-Is:'], 'result': {'type': 'Server', 'device': 'Tor router'}},
        {'name': 'Tor Exit Router HTTP header', 'filter': 'tcp/9001', 'test': 'contains', 'contains': ['data', 'X-Your-Address-Is:'], 'result': {'type': 'Server', 'device': 'Tor router'}},
        # Operating system rules
        {'name': 'Windows NetBIOS', 'filter': 'udp/137', 'test': 'contains', 'contains': ['data', 'NetBIOS Response'], 'result': {'type': 'Server', 'device': 'Windows System'}},
        {'name': 'Windows with MS HTTPAPI Web Server', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['data', 'Server: Microsoft-HTTPAPI'], 'result': {'type': 'Server', 'device': 'Windows Server'}},
        {'name': 'MS FTP Service', 'filter': 'tcp/21', 'test': 'contains', 'contains': ['data', 'Microsoft FTP Service'], 'result': {'type': 'Server', 'device': 'Windows system'}},
        {'name': 'Ubuntu-ssh', 'filter': 'tcp/22', 'test': 'contains', 'contains': ['data', 'ubuntu'], 'result': {'type': 'Server', 'device': 'Ubuntu Server'}},
        {'name': 'Ubuntu Apache header', 'filter': 'tcp/80', 'test': 'regex', 'regex': 'Server\: Apache\/\d+\.\d+\.\d+ \(Ubuntu\)', 'result': {'type': 'Server', 'device': 'Ubuntu Server', 'os': 'Linux'}},
        {'name': 'Ubuntu Apache header', 'filter': 'tcp/443', 'test': 'regex', 'regex': 'Server\: Apache\/\d+\.\d+\.\d+ \(Ubuntu\)', 'result': {'type': 'Server', 'device': 'Ubuntu Server', 'os': 'Linux'}},
        {'name': 'Ubuntu Apache header', 'filter': 'tcp/8080', 'test': 'regex', 'regex': 'Server\: Apache\/\d+\.\d+\.\d+ \(Ubuntu\)', 'result': {'type': 'Server', 'device': 'Ubuntu Server', 'os': 'Linux'}},
        {'name': 'Ubuntu Apache default page', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['html', '<title>Apache2 Ubuntu Default Page: It works</title>'], 'result': {'type': 'Server', 'device': 'Ubuntu server', 'os': 'Linux'}},
        {'name': 'Debian ssh header', 'filter': 'tcp/22', 'test': 'regex', 'regex': 'SSH-\d+\.\d+-OpenSSH_\d+\.\d+p\d+ Debian', 'result': {'type': 'Server', 'device': 'Debian Server', 'os': 'Linux'}},
        {'name': 'Ubuntu ssh header', 'filter': 'tcp/22', 'test': 'regex', 'regex': 'SSH-\d+\.\d+-OpenSSH_\d+\.\d+p\d+ Ubuntu', 'result': {'type': 'Server', 'device': 'Ubuntu Server', 'os': 'Linux'}},
        {'name': 'Ubuntu ssh header port 2222', 'filter': 'tcp/2222', 'test': 'regex', 'regex': 'SSH-\d+\.\d+-OpenSSH_\d+\.\d+p\d+ Ubuntu', 'result': {'type': 'Server', 'device': 'Ubuntu Server', 'os': 'Linux'}},
        {'name': 'Debian bind header', 'filter': 'udp/53', 'test': 'contains', 'contains': ['data', '-Debian'], 'result': {'type': 'Server', 'device': 'Debian Server', 'os': 'Linux'}},
        {'name': 'FreeBSD Apache header', 'filter': 'tcp/80', 'test': 'regex', 'regex': 'Apache/\d+\.\d+\.\d+ \(FreeBSD\)', 'result': {'type': 'Server', 'device': 'FreeBSD Server', 'os': 'FreeBSD'}},
        {'name': 'RedHat DNS header', 'filter': 'udp/53', 'test': 'contains', 'contains': ['data', 'RedHat'], 'result': {'type': 'Server', 'device': 'RedHat Server', 'os': 'Linux'}},
        # From here, unreliable rules
        {'name': 'Apache Red Hat', 'filter': 'tcp/80', 'test': 'regex', 'regex': 'Server: Apache/\d+\.\d+\.\d+ \(Red Hat Linux\)', 'result': {'type': 'Server', 'device': 'Red Hat Linux Server'}},
        {'name': 'ADSL Router', 'filter': 'tcp/80', 'test': 'contains', 'contains': ['data', 'Basic realm=\"ADSL Modem\"'], 'result': {'type': 'Router', 'device': 'Unknown'}},
        {'name': 'DVR DNVRS-Webs web server', 'filter': 'tcp/81', 'test': 'contains', 'contains': ['data', 'Server: DNVRS-Webs'], 'result': {'type': 'Camera', 'device': 'Unknown'}}, # broad rule, not sure which model this is
        {'name': 'RomPager UPnP', 'filter': 'tcp/7547', 'test': 'contains', 'contains': ['data', 'RomPager'], 'result': {'type': 'Router', 'device': 'Unknown'}},
        {'name': 'Apache Win32 header', 'filter': 'tcp/80', 'test': 'regex', 'regex': 'Apache\/\d+\.\d+\.\d+ \(Win32\)', 'result': {'type': 'Server', 'device': 'Windows Server'}},
        {'name': 'Apache Win32 header', 'filter': 'tcp/8080', 'test': 'regex', 'regex': 'Apache\/\d+\.\d+\.\d+ \(Win32\)', 'result': {'type': 'Server', 'device': 'Windows Server'}},
        {'name': 'Apache CentOS', 'filter': 'tcp/80', 'test': 'regex', 'regex': 'Server: Apache/\d+\.\d+\.\d+ \(CentOS\)', 'result': {'type': 'Server', 'device': 'CentOS Linux Server', 'os': 'Linux'}},
        {'name': 'GoAhead-Webs IoT web server', 'filter': 'tcp/443', 'test': 'contains', 'contains': ['data', 'GoAhead-Webs'], 'result': {'type': 'IoT', 'device': 'Unknown'}},
]


def dfilter(data, f):
    """
    Filter shodan port data compared based on a given filter
    Filter are under the form protocol/port
    """
    ff = f.split("/")
    return (data['transport'] == ff[0]) and (data['port'] == int(ff[1]))


def get_key(dictionary, keys, i):
    """
    Get a value from a dictionary
    """
    if (len(keys) - 1) == i:
        return dictionary[keys[i]]
    else:
        return get_key(dictionary[keys[i]], keys, i+1)


def fingerprint(data):
    now = datetime.now()
    for signature in FINGERPRINT:
        for d in data:
            # Check that scan is not older than 6 months
            scandate = parse(d['timestamp'])
            if scandate > now - timedelta(days=180):
                if dfilter(d, signature['filter']):
                    if signature['test'] == 'contains':
                        if '.' in signature['contains'][0]:
                            try:
                                val = get_key(d, signature['contains'][0].split("."), 0)
                                if val:
                                    if signature['contains'][1].lower() in val.lower():
                                        res = signature['result']
                                        res['rule'] = signature['name']
                                        res['found'] = True
                                        return res
                            except KeyError:
                                # Key not in the dictionnary
                                pass
                        else:
                            if signature['contains'][0] in d:
                                if signature['contains'][1].lower() in d[signature['contains'][0]].lower():
                                    res = signature['result']
                                    res['rule'] = signature['name']
                                    res['found'] = True
                                    return res
                    elif signature['test'] == 'regex':
                        if re.search(signature['regex'], d['data'], flags=re.IGNORECASE):
                            res = signature['result']
                            res['rule'] = signature['name']
                            res['found'] = True
                            return res

    return {'found': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fingerprint a system based on Shodan information')
    parser.add_argument('--ip', '-i', help='IP')
    parser.add_argument('--file', '-f', help='IP')
    parser.add_argument('--history', '-H', action='store_true',
            help='Also consider Shodan history for the past six months')
    parser.add_argument('--key', '-k', help='Shodan API key')

    args = parser.parse_args()

    # Deal with the key first
    if args.key:
        key = args.key
    else:
        cpath = os.path.expanduser('~/.shodan/api_key')
        if os.path.isfile(cpath):
            with open(cpath, 'r') as f:
                key = f.read().strip()
        else:
            print("No API key found")
            sys.exit(1)

    api = shodan.Shodan(key)
    if args.ip:
        try:
            res = api.host(args.ip, history=args.history)
        except shodan.exception.APIError:
            print("IP not found in Shodan")
        else:
            finger = fingerprint(res['data'])
            if finger['found']:
                print("%s : %s (%s)" % (finger['type'], finger['device'], finger['rule']))
            else:
                print("Unknown system")
    else:
        if args.file:
            with open(args.file, 'r') as f:
                data = f.read().split()
            for ip in data:
                try:
                    res = api.host(ip, history=True)
                except shodan.exception.APIError:
                    print("%s ; Not found ; Unknown ; " % ip)
                else:
                    finger = fingerprint(res['data'])
                    if finger['found']:
                        print("%s ; %s ; %s ; %s" % (ip, finger['type'], finger['device'], finger['rule']))
                    else:
                        print("%s ; Unknown ; Unknown ; " % ip)
                time.sleep(0.5)

        else:
            print("You need to provide an IP or a file")
            parser.print_help()
            sys.exit(1)
