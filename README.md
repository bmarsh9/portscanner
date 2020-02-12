# portscanner
portscanner written in python to provide JSON data of targets

# install
##### nmap must be already installed
pip3 install python-nmap

# usage
```
from scanner import PortScan
import json
results = PortScan(target="10.1.1.123",arguments="-p 1-65535 -T4 -A -v -O").execute()
print(json.dumps(results,indent=4))
```
