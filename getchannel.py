from scapy.all import Dot11, Dot11Beacon, RadioTap, sniff
import argparse
from threading import Thread
import time
import os
from itertools import cycle

def change_channel():
    global interface
    channels = [1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165]
    ccycle = cycle(channels)
    while True:
        os.system("iwconfig {} channel {}".format(interface,next(ccycle)))
        # switch channel from 1 to 14 each 0.5s
        time.sleep(0.1)

def packetHandler(p):
    global ssid
    if p.haslayer(Dot11):
        if p.haslayer(Dot11Beacon):
            stats = p[Dot11Beacon].network_stats()
            if stats["ssid"] == ssid:
                try:
                    channel = stats["channel"]
                except:
                    if p.haslayer(RadioTap): 
                        try:
                            channel = (p[RadioTap].Channel - 5000 ) // 5
                        except:
                            pass
                    else:
                        print(p)
                print("{}:{}".format(stats["ssid"], channel))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--ssid')
    parser.add_argument('-i', '--interface')
    args = parser.parse_args()
    ssid = args.ssid
    interface = args.interface
    t = Thread(target=change_channel)
    t.daemon = True
    t.start()
    sniff(iface="wlp2s0mon", filter="wlan type mgt subtype beacon", prn=packetHandler)
    
