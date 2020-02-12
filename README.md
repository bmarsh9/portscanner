# portscanner
portscanner written in python to provide JSON data of targets

# install
##### nmap must be already installed
pip3 install python-nmap

# usage
```
from scanner import PortScan
import json
results = PortScan(target="10.100.10.123",arguments="-p 1-65535 -T4 -A -v -O").execute()
print(json.dumps(results,indent=4))
```

# sample output
```
{
    "targets": [
        "10.100.10.123"
    ],
    "scan_start": "2020-02-12 14:41:34",
    "scan_end": "2020-02-12 14:42:01",
    "elapsed": "27.61",
    "uphosts": "1",
    "downhosts": "0",
    "totalhosts": "1",
    "percentage_up": 100.0,
    "uniq_family": 1,
    "uniq_os": 1,
    "total_ports_open": 4,
    "uniq_ports_open": 4,
    "total_services": 4,
    "uniq_services": 4,
    "host_data": [
        {
            "ip": "10.100.10.123",
            "hostname": "",
            "state": "up",
            "uptime": "1469875",
            "last_boot": "Sun Jan 26 14:23:39 2020",
            "os": "Linux 3.7 - 3.10",
            "accuracy": "100",
            "type": "general purpose",
            "vendor": "Linux",
            "osfamily": "Linux",
            "osgen": "3.X",
            "os_data": [
                {
                    "name": "Linux 3.7 - 3.10",
                    "accuracy": "100",
                    "line": "65736",
                    "osclass": [
                        {
                            "type": "general purpose",
                            "vendor": "Linux",
                            "osfamily": "Linux",
                            "osgen": "3.X",
                            "accuracy": "100",
                            "cpe": [
                                "cpe:/o:linux:linux_kernel:3"
                            ]
                        }
                    ]
                }
            ],      
            "port_data": [
                {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "7.9p1 Debian 10",
                    "extrainfo": "protocol 2.0",
                    "conf": "10",
                    "cpe": "cpe:/o:linux:linux_kernel",
                    "script": {
                        "ssh-hostkey": "\n  2048 16:e1:be:0e:bc:6a:68:fb:49:ab:02:5e:cd:b"
                    },
                    "port": 22,
                    "protocol": "tcp"
                },
                {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "rise",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "conf": "3",
                    "cpe": "",
                    "script": {
                        "fingerprint-strings": "\n  DNSStatusRequestTCP, DNSVersionBindReqTCP: \n    HTTP/1.1 400 Illegal character CNTL=0x0\n    Content-Type: text/html;charset=iso-8859-1\n    Content-Length: 69\n    Connection: close\n    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>\n  GetRequest: \n    HTTP/1.1 200 OK\n    Date: Wed, 12 Feb 2020 19:41:31 GMT\n    Access-Control-Allow-Origin: *\n    Content-Type: application/json;charset=utf-8\n    Content-Length: 141\n    \"data\" : \"https://10.100.10.123:7473/db/data/\",\n    \"management\" : \"https://10.100.10.123:7473/db/manage/\",\n    \"bolt\" : \"bolt://10.100.10.123:7687\"\n  HTTPOptions: \n    HTTP/1.1 204 No Content\n    Date: Wed, 12 Feb 2020 19:41:31 GMT\n    Access-Control-Allow-Origin: *\n    Allow: OPTIONS,HEAD,GET\n  Help: \n    HTTP/1.1 400 No URI\n    Content-Type: text/html;charset=iso-8859-1\n    Content-Length: 49\n    Connection: close\n    <h1>Bad Message 400</h1><pre>reason: No URI</pre>\n  RPCCheck: \n    HTTP/1.1 400 Illegal character OTEXT=0x80\n    Content-Type: text/html;charset=iso-8859-1\n    Content-Length: 71\n    Connection: close\n    <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>\n  RTSPRequest: \n    HTTP/1.1 400 Unknown Version\n    Content-Type: text/html;charset=iso-8859-1\n    Content-Length: 58\n    Connection: close\n    <h1>Bad Message 400</h1><pre>reason: Unknown Version</pre>\n  SSLSessionReq: \n    HTTP/1.1 400 Illegal character CNTL=0x16\n    Content-Type: text/html;charset=iso-8859-1\n    Content-Length: 70\n    Connection: close\n    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>",
                        "ssl-cert": "Subject: commonName=0.0.0.0\nIssuer: commonName=0.0.0.0\nPublic Key type: rsa\nPublic Key bits: 2048\nSignature Algorithm: sha512WithRSAEncryption\nNot valid before: 2018-01-31T22:51:38\nNot valid after:  9999-12-31T23:59:59\nMD5:   9aaa f1ac d755 abbf c64f 6771 4d05 1c8d\nSHA-1: 2410 6516 6897 4e2d f942 6605"
                    },
                    "port": 7473,
                    "protocol": "tcp"
                },
                {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "neo4j",
                    "product": "",
                    "version": "",
                    "extrainfo": "",
                    "conf": "3",
                    "cpe": "",
                    "script": {
                        "fingerprint-strings": "\n  DNSStatusRequestTCP, DNSVersionBindReqTCP: \n    HTTP/1.1 400 Illegal character CNTL=0x0\n    Content-Type: text/html;charset=iso-8859-1\n    Content-Length: 69\n    Connection: close\n    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>\n  GetRequest: \n    HTTP/1.1 200 OK\n    Date: Wed, 12 Feb 2020 19:41:20 GMT\n    Access-Control-Allow-Origin: *\n    Content-Type: application/json;charset=utf-8\n    Content-Length: 139\n    \"data\" : \"http://10.100.10.123:7474/db/data/\",\n    \"management\" : \"http://10.100.10.123:7474/db/manage/\",\n    \"bolt\" : \"bolt://10.100.10.123:7687\"\n  HTTPOptions: \n    HTTP/1.1 204 No Content\n    Date: Wed, 12 Feb 2020 19:41:20 GMT\n    Access-Control-Allow-Origin: *\n    Allow: OPTIONS,HEAD,GET\n  Help: \n    HTTP/1.1 400 No URI\n    Content-Type: text/html;charset=iso-8859-1\n    Content-Length: 49\n    Connection: close\n    <h1>Bad Message 400</h1><pre>reason: No URI</pre>\n  RPCCheck: \n    HTTP/1.1 400 Illegal character OTEXT=0x80\n    Content-Type: text/html;charset=iso-8859-1\n    Content-Length: 71\n    Connection: close\n    <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>\n  RTSPRequest: \n    HTTP/1.1 400 Unknown Version\n    Content-Type: text/html;charset=iso-8859-1\n    Content-Length: 58\n    Connection: close\n    <h1>Bad Message 400</h1><pre>reason: Unknown Version</pre>\n  SSLSessionReq: \n    HTTP/1.1 400 Illegal character CNTL=0x16\n    Content-Type: text/html;charset=iso-8859-1\n    Content-Length: 70\n    Connection: close\n    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>"
                    },
                    "port": 7474,
                    "protocol": "tcp"
                },
                {
                    "state": "open",
                    "reason": "syn-ack",
                    "name": "websocket",
                    "product": "Neo4j Bolt protocol",
                    "version": "",
                    "extrainfo": "",
                    "conf": "10",
                    "cpe": "cpe:/a:neo4j:neo4j",
                    "port": 7687,
                    "protocol": "tcp"
                }
            ]
        }
    ]
}

```

# testing -- do the math
  * nmap flags: `-p 1-65535 -T4 -A -v -O`
  * desc: full TCP port scan with OS detection
  * avg time per host that is up: 27 seconds
  * avg time per host that is down: 2 seconds

  * nmap flags: `-T4 -A -v -O`
  * desc: only popular tcp port scan with OS detection
  * avg time per host that is up: 17 seconds
  * avg time per host that is down: 1 seconds
