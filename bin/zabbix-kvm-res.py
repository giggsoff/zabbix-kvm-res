#!/usr/bin/python -tt
# -*- coding: utf-8 -*-

# zabbix-kvm-res.py
# this tool returns information for zabbix monitoring (and possibly other monitoring solutions)
import libvirt
import sys
import json
from xml.etree import ElementTree

from optparse import OptionParser

uri = 'qemu:///system'


def main():
    options = parse_args()
    r = ''
    if options.resource == "pool":
        if options.action == "list":
            r = pool_list(options)
        elif options.action == "total":
            r = pool_total(options)
        elif options.action == "used":
            r = pool_used(options)
        elif options.action == "free":
            r = pool_free(options)
        elif options.action == "active":
            r = pool_isActive(options)
        elif options.action == "UUID":
            r = pool_uuid(options)
    elif options.resource == "net":
        if options.action == "list":
            r = net_list(options)
        elif options.action == "active":
            r = net_isActive(options)
        elif options.action == "UUID":
            r = net_uuid(options)
    elif options.resource == "domain":
        if options.action == "list":
            r = domain_list(options)
        elif options.action == "active":
            r = domain_isActive(options)
        elif options.action == "UUID":
            r = domain_uuid(options)
        elif options.action == "name":
            r = domain_name(options)
        elif options.action == "project":
            r = domain_project(options)
        elif options.action == "BIN" or options.action == "BOUT":
            r = domain_net(options)
    print r


def domain_list(options):
    conn = kvm_connect()
    r = {"data": []}
    try:
        conn.listAllDomains(0)
    except:
        domains = []
        for dom_id in conn.listDomainsID():
            r['data'].append({"{#DOMAINNAME}": conn.lookupByID(dom_id).name()})
    else:
        for domain in conn.listAllDomains(0):
            r["data"].append({"{#DOMAINNAME}": domain.name()})

    return json.dumps(r, indent=2, sort_keys=True, encoding="utf-8")


def domain_isActive(options):
    conn = kvm_connect()
    return conn.lookupByName(options.domain).isActive()


def domain_uuid(options):
    conn = kvm_connect()
    return conn.lookupByName(options.domain).UUIDString()


def get_devices(dom, type):
    devices = []

    # Create a XML tree from the domain XML description.
    tree = ElementTree.fromstring(dom.XMLDesc(0))
    for target in tree.findall("devices/%s/target" % type):
        dev = target.get("dev")
        if dev not in devices:
            devices.append(dev)

    return devices


def get_network_devices(dom):
    return get_devices(dom, 'interface')


def get_disk_devices(dom):
    return get_devices(dom, 'disk')


def domain_net(options):
    conn = kvm_connect()
    domain = conn.lookupByName(options.domain)
    result = 0
    try:
        vifs = get_network_devices(domain)
        stats = domain.interfaceStats(vifs[0])
        if options.action == "BIN":
            result = str(stats[0])
        elif options.action == "BOUT":
            result = str(stats[4])
    except libvirt.libvirtError:
        pass
    return result


def domain_name(options):
    conn = kvm_connect()
    domain = conn.lookupByName(options.domain)
    tree = ElementTree.fromstring(domain.XMLDesc(0))
    for name in tree.find("metadata/nova:instance/nova:name"):
        return name


def domain_project(options):
    conn = kvm_connect()
    domain = conn.lookupByName(options.domain)
    tree = ElementTree.fromstring(domain.XMLDesc(0))
    for project in tree.find("metadata/nova:instance/nova:owner/nova:project"):
        return project


def net_list(options):
    conn = kvm_connect()
    r = {"data": []}
    try:
        conn.listAllNetworks(0)
    except:
        for net in conn.listNetworks():
            r["data"].append({"{#NETNAME}": net})
    else:
        for net in conn.listAllNetworks(0):
            r["data"].append({"{#NETNAME}": net.name()})

    return json.dumps(r, indent=2, sort_keys=True, encoding="utf-8")


def net_isActive(options):
    conn = kvm_connect()
    return conn.networkLookupByName(options.net).isActive()


def net_uuid(options):
    conn = kvm_connect()
    return conn.networkLookupByName(options.net).UUIDString()


def pool_list(options):
    conn = kvm_connect()
    r = {"data": []}
    try:
        conn.listAllStoragePools(0)
    except:
        for pool in conn.listStoragePools():
            r["data"].append({"{#POOLNAME}": pool})
    else:
        for pool in conn.listAllStoragePools(0):
            r["data"].append({"{#POOLNAME}": pool.name()})

    return json.dumps(r, indent=2, sort_keys=True, encoding="utf-8")


def pool_total(options):
    return pool_info(options)[1]


def pool_used(options):
    return pool_info(options)[2]


def pool_free(options):
    return pool_info(options)[3]


def pool_isActive(options):
    conn = kvm_connect()
    return conn.storagePoolLookupByName(options.pool).isActive()


def pool_uuid(options):
    conn = kvm_connect()
    return conn.storagePoolLookupByName(options.pool).UUIDString()


def pool_info(options):
    if options.pool == None:
        sys.stderr.write("There was an error connecting to pool.\n")
        exit(1)
    conn = kvm_connect()
    try:
        info = conn.storagePoolLookupByName(options.pool).info()
    except:
        sys.stderr.write("There was an error connecting to pool '" + options.pool + "'.")
        exit(1)
    return info


def kvm_connect():
    try:
        conn = libvirt.openReadOnly(uri)
    except:
        sys.stderr.write("There was an error connecting to the local libvirt daemon using '" + uri + "'.")
        exit(1)
    return conn


def parse_args():
    parser = OptionParser()
    valid_resource_types = ["pool", "net", "domain"]
    valid_actions = ["discover", "capacity", "allocation", "available"]

    parser.add_option("", "--resource", dest="resource", help="Resource type to be queried", action="store",
                      type="string", default=None)
    parser.add_option("", "--action", dest="action", help="The name of the action to be performed", action="store",
                      type="string", default=None)

    parser.add_option("", "--pool", dest="pool", help="The name of the pool to be queried", action="store",
                      type="string", default=None)
    parser.add_option("", "--net", dest="net", help="The name of the net to be queried", action="store", type="string",
                      default=None)
    parser.add_option("", "--domain", dest="domain", help="The name of the domain to be queried", action="store",
                      type="string", default=None)

    (options, args) = parser.parse_args()
    if options.resource not in valid_resource_types:
        parser.error("Resource has to be one of: " + ", ".join(valid_resource_types))

    if options.resource == "pool":
        pool_valid_actions = ['list', 'total', 'used', 'free', 'active', 'UUID']
        if options.action not in pool_valid_actions:
            parser.error("Action hass to be one of: " + ", ".join(pool_valid_actions))
    elif options.resource == "net":
        net_valid_actions = ['list', 'active', 'UUID']
        if options.action not in net_valid_actions:
            parser.error("Action hass to be one of: " + ", ".join(net_valid_actions))
    elif options.resource == "domain":
        domain_valid_actions = ['list', 'active', 'UUID', 'BIN', 'BOUT', 'name', 'project']
        if options.action not in domain_valid_actions:
            parser.error("Action hass to be one of: " + ", ".join(domain_valid_actions))

    return options


if __name__ == "__main__":
    main()
