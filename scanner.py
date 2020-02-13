#!/usr/bin/python3
'''
Description: Scan a network range and report on ports,services,os version
Install: pip3 install python-nmap
Usage:
    from scanner import PortScan
    import json
    results = PortScan(target="10.1.1.123",arguments="-p 1-65535 -T4 -A -v -O").execute()
    print(json.dumps(results,indent=4))
'''
import nmap
import datetime

class PortScan():
    def __init__(self,target,arguments,include_down_hosts=False,to_csv=False):
        self.nm = nmap.PortScanner()
        self.target = target
        self.arguments = arguments
        self.include_down_hosts = include_down_hosts
        self.to_csv = to_csv

    def execute(self):
        # start scan
        self.nm.scan(hosts=self.target, arguments=self.arguments)

        # output options
        if self.to_csv:
            return self.nm.csv()
        return self.to_json()

    def to_json(self):
        dataset = {"host_data":[],"targets":self.target}

        # collect scan metrics
        family_list = []
        os_list = []
        services = []
        ports_open = []

        uniq_family = 0
        uniq_os = 0
        total_ports_open = 0
        uniq_ports_open = 0
        total_services = 0
        uniq_services = 0

        # get overall scan details
        scan_start = datetime.datetime.strptime(self.nm.scanstats()["timestr"],"%a %b %d %H:%M:%S %Y")
        scan_end = scan_start + datetime.timedelta(0,float(self.nm.scanstats()["elapsed"]))
        dataset["scan_start"] = str(scan_start)
        dataset["scan_end"] = str(scan_end.replace(microsecond=0))

        scan_stats_keys = ["elapsed","uphosts","downhosts","totalhosts"]
        for key,value in self.nm.scanstats().items():
            if key in scan_stats_keys:
                dataset[key] = float(value)

        percentage_up = (int(self.nm.scanstats()["uphosts"]) / int(self.nm.scanstats()["totalhosts"]) *100)
        dataset["percentage_up"] = percentage_up

        # enumerate hosts in scan
        for host in self.nm.all_hosts():
            # set host information
            data = {"port_data":[],"ip":self.nm[host]["addresses"]["ipv4"],"hostname":self.nm[host].hostname(),
                "state":self.nm[host].state(),"uptime":None,"last_boot":None}

            if self.nm[host].state() == "up":
                if self.nm[host].get("uptime"):
                    data["uptime"] = self.nm[host]["uptime"].get("seconds")
                    data["last_boot"] = self.nm[host]["uptime"].get("lastboot")

                # enumerate OS version
                indexed_osclass_keys = ["type","vendor","osfamily","osgen"]
                if self.nm[host].get("osmatch"):
                    # get os match with highest accuracy
                    likely_os = sorted(self.nm[host]["osmatch"],key=lambda i: int(i["accuracy"]),reverse=True)[0]
                    data["os"] = likely_os.get("name","unknown")
                    # add uniq os type
                    if likely_os.get("name","unknown") not in os_list:
                        uniq_os += 1
                        os_list.append(likely_os.get("name","unknown"))

                    data["accuracy"] = likely_os.get("accuracy",0)

                    # get os_class match with highest accuracy
                    if likely_os.get("osclass"):
                        likely_osclass = sorted(likely_os["osclass"],key=lambda i: int(i["accuracy"]),reverse=True)[0]
                        for key,value in likely_osclass.items():
                            if key in indexed_osclass_keys:
                                # add uniq os family type
                                if key == "osfamily" and value not in family_list:
                                    uniq_family += 1
                                    family_list.append(value)
                                data[key] = value
                    data["os_data"] = self.nm[host]["osmatch"] # add full os data

                # per host port metrics
                host_services_list = []
                host_ports_open_list = []
                host_ports_open = 0
                host_services = 0

                # enumerate all protocols
                indexed_port_keys = ["state","reason","name","product","version","extrainfo","conf","cpe","script"]
                for proto in self.nm[host].all_protocols():
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        temp = {}
                        for key,value in self.nm[host][proto][port].items(): # iterate over all ports
                            if key in indexed_port_keys:
                                # add to metrics
                                if key == "state" and value == "open":
                                    host_ports_open += 1
                                    host_ports_open_list.append(port)
                                    total_ports_open += 1
                                    if port not in ports_open:
                                        ports_open.append(port)
                                        uniq_ports_open += 1
                                elif key == "name" and value and value != "":
                                    host_services += 1
                                    host_services_list.append(value)
                                    total_services += 1
                                    if value not in services:
                                        services.append(value)
                                        uniq_services += 1
                                temp[key] = value
                        # finalize host data
                        temp["port"] = port
                        temp["protocol"] = proto
                        data["port_data"].append(temp)
                data["ports_open"] = host_ports_open
                data["services"] = host_services
                dataset["host_data"].append(data)
            # down host
            else:
                if self.include_down_hosts:
                    dataset["host_data"].append(data)

        # insert overall metrics
        dataset["uniq_family"] = uniq_family
        dataset["uniq_os"] = uniq_os
        dataset["total_ports_open"] = total_ports_open
        dataset["uniq_ports_open"] = uniq_ports_open
        dataset["total_services"] = total_services
        dataset["uniq_services"] = uniq_services

        # return results of the scan
        return dataset
