#!/usr/bin/env python3.3
#
# Read a report.xml file and output a graphviz graph of the nodes
#
import xml.etree.ElementTree as ET

if __name__=="__main__":
    import sys
    root = ET.parse(sys.argv[1])
    macs = set()
    ssids = set()
    print("digraph ssids {")
    for ssidnode in root.findall('.//ssid'):
        macs.add(ssidnode.attrib['mac'])
        ssids.add(ssidnode.attrib['ssid'])
        print('  "{}" -> "{}";'.format(ssidnode.attrib['mac'],ssidnode.attrib['ssid']))

    # Send through the attributes
    # Make all of the boxes
    for mac in macs:
        print('  "{}" [shape=box]'.format(mac))

    # color all of the SSIDs
    c = 1
    for ssid in ssids:
        r = (c)//3
        g = (c+1)//3
        b = (c+2)//3
        color = "#{:02X}{:02X}{:02X}".format(255-r*16,255-g*16,255-b*16)
        c += 1
        if c/3>4:
            c = 0
        print('  "{}" [color="{}",style=filled]'.format(ssid,color))
        for macnode in root.findall(".//ssid/[@ssid='{}']".format(ssid)):
            print('  "{}" [color="{}",style=filled]'.format(macnode.attrib['mac'],color))
    print("}")
    
