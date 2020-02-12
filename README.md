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

# testing -- do the math

  * nmap flags: `-p 1-65535 -T4 -A -v -O`
  * desc: full TCP port scan with OS detection
  * avg time per host that is up: 27 seconds
  * avg time per host that is down: 2 seconds

  * nmap flags: `-T4 -A -v -O`
  * desc: only popular tcp port scan with OS detection
  * avg time per host that is up: 17 seconds
  * avg time per host that is down: 1 seconds
