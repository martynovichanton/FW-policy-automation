import requests
import urllib3
from datetime import datetime
import json
import os
from ipaddress import IPv4Network
from bs4 import BeautifulSoup

urllib3.disable_warnings()

session = requests.Session()

def build_azure_ips():
    logdir = "log"
    if not os.path.exists(f"{logdir}"):
        os.mkdir(f"{logdir}")

    now = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    jsonfilename = f"{logdir}/azure_ips_{now}.json"
    scriptfilename = f"{logdir}/fw_objects_update_azure_{now}.txt"
    ipsfilename = f"{logdir}/ips_{now}.txt"
    url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
    download_json(jsonfilename, url)
    ips = parse_json(jsonfilename, ipsfilename)
    print(json.dumps(ips, sort_keys=False, indent=4))
    generate_script(ips, scriptfilename)
                 
def download_json(jsonfilename, url):
    page = session.request("GET", url,  verify=False)
    # print(page.text)

    soup = BeautifulSoup(page.content, "html.parser")
    link = soup.find('a', {'data-bi-containername':'download retry'})['href']
    # print(link)

    file = session.request("GET", link,  verify=False, stream=True)

    with open(f"{jsonfilename}", 'wb') as f:
        for chunk in file.iter_content(chunk_size=1024):  
            #print(chunk.decode("utf-8"))
            f.write(chunk)

def parse_json(jsonfilename, ipsfilename):
    ipsfile = open(ipsfilename, "w")
    locations = ["AzureEventGrid", "ActionGroup", "AzureActiveDirectory"]
    ips = {}
    # ips = {
    #     "AzureEventGrid":["ip1","ip2"],
    #     "AzureDigitalTwins":["ip1","ip2"]
    # }

    with open(f"{jsonfilename}", "r") as f:
        data = json.load(f)
    # print(data)
    for v in data['values']:
        if any(l == v['name'] for l in locations):
            ips[v['name']] = []
            for ip in v['properties']['addressPrefixes']:
                if validate_ip(ip):
                    ips[v['name']].append(ip)
                    ipsfile.write(ip.replace('"','') + "\n")
    
    ipsfile.close()

    return ips

def generate_script(ips, scriptfilename):
    f = open(f"{scriptfilename}", "w")

    # create addresses
    f.write('config firewall address\n')
    for location in ips:
        for i in ips[location]:
            ip = i.split("/")[0]
            subnet = i.split("/")[1]
            f.write(f'edit Azure_{location}_{ip}_{subnet}\n')
            f.write(f'set subnet {ip}/{subnet}\n')
            f.write(f'set comment Azure_{location}_{ip}_{subnet}\n')
            f.write('next\n')
    f.write('end\n')
    
    # create address groups and add the members per group
    groups = []
    f.write('config firewall addrgrp\n')
    for location in ips:
        groups.append(f'Azure_Nets_{location}')
        members = ''
        f.write(f'edit \"Azure_Nets_{location}\"\n')
        for i in ips[location]:
            ip = i.split("/")[0]
            subnet = i.split("/")[1]
            members = members + f'\"Azure_{location}_{ip}_{subnet}\" '
        f.write(f'set member {members}\n')
        f.write('next\n')
    f.write('end\n')

    # add groups to the main group
    members = ''
    for group in groups:
        members = members + f'\"{group}\" '

    f.write('config firewall addrgrp\n')
    f.write('edit \"Azure_Nets\"\n')
    f.write(f'set member {members}\n')
    f.write('next\n')
    f.write('end\n')

    f.close()

def validate_ip(ip):
    # ip = ip/subnetmask or ip
    try:
        if IPv4Network(ip):
            return True
        else:
            return False
    except ValueError as e:
        return False


if __name__ == "__main__":
    build_azure_ips()