# shodan_fingerprinter

Scripts fingerprinting systems based on shodan.io data

## Installation and Configuration

You need to install the [shodan python library](https://github.com/achillean/shodan-python) first : `pip install shodan`

You need to get a [Shodan API key](https://developer.shodan.io/)

Then store this API key in `~/.shodan/api_key` (shared configuration file with the [Shodan CLI tool](https://cli.shodan.io/)).

## Usage

```
Fingerprint a system based on Shodan information

optional arguments:
  -h, --help            show this help message and exit
  --ip IP, -i IP        IP
  --file FILE, -f FILE  IP
  --history, -H         Also consider Shodan history for the past six months
  --key KEY, -k KEY     Shodan API key
```

## Example

Fingerprint one IP :
```
$ python shodanfingerprint.py  -H -i 203.153.111.118
Router : MikroTik Router (MikroTik)
```

Fingerprint a list of IPs:
```
$ python shodanfingerprint.py -H -f ~/temp/mikrotik
203.153.111.118 ; Router ; MikroTik Router ; MikroTik
181.57.217.158 ; Router ; MikroTik Router ; MikroTik
```

**Warning:** this fingerprint may not be reliable for many different reasons. It could be that the system does not have any identifiable fingerprint, that a router is actually using Ubuntu or another operating system (and thus identified as a server), or that a router is identified but the traffic is actually coming from a system on the internal network of this router. Etc.

## Signatures

This tool relies on signature to identify systens, for instance (taken from `shodan_fingerprint.py`):
```python
{'name': 'Technicolor SNMP', 'filter': 'udp/161', 'test': 'contains', 'contains': ['data', 'Technicolor'], 'result': {'type': 'Router', 'device': 'Technicolor'}},
```

This signature will check if the `data` field of data gathered on UPD port 161 contains the word `Technicolor`. If yes, it means that this system is a Technicolor Router.

## License

This code is released under the [MIT License](LICENSE).
