from scapy.all import *
import argparse
import os
import time
import threading

state = {}
pckts = ""
prot = {}
prev_msg='x:x'
ptime = ''

def processCommandline():
    parser = argparse.ArgumentParser(description="WiFi panel states")
    parser.add_argument("pcapfile", help="pcap file")
    args = parser.parse_args()
    return args

def scanPackets():
    global pckts
    pckts = sniff(iface="wlan0", prn=lambda p: analysePacket(p))

def readPackets():
    global pckts
    args = processCommandline()
    print("Processing {}. Please wait!".format(args.pcapfile))
    # pckts = rdpcap(args.pcapfile)
    reader = PcapReader(args.pcapfile)
    print("Read {} packets from file.".format(len(pckts)))
    for p in reader:
        analyseProtocol(p)

# Type 0    :   Management
# Type 1    :   Control
# Type 2    :   Data

panels = [
    '68:67:25:57:20:d4',
    '68:67:25:54:4f:10',
    '68:67:25:56:ee:e0',  
    '68:67:25:55:c7:30',
    '68:67:25:54:a9:dc',   
    '58:cf:79:dc:fc:90',
    '58:cf:79:dc:94:e4',
    '58:cf:79:dc:fc:c8',
    '58:cf:79:dc:7e:d8',
    '58:cf:79:dc:7e:1c',
    '58:cf:79:dd:2a:bc',
    '58:cf:79:dc:b3:a8',
    '58:cf:79:dc:9d:1c',
]

dot11protocol = [
    {'type': 0, 'subtype': 0,  'message': 'Association request'},
    {'type': 0, 'subtype': 1,  'message': 'Association response'},
    {'type': 0, 'subtype': 2,  'message': 'Reassociation request'},
    {'type': 0, 'subtype': 3,  'message': 'Reassociation response'},
    {'type': 0, 'subtype': 4,  'message': 'Probe request'},
    {'type': 0, 'subtype': 5,  'message': 'Probe response'},
    {'type': 0, 'subtype': 6,  'message': 'Timing advertisement'},
    {'type': 0, 'subtype': 7,  'message': 'Reserved'},
    {'type': 0, 'subtype': 8,  'message': 'Beacon'},
    {'type': 0, 'subtype': 9,  'message': 'ATIM'},
    {'type': 0, 'subtype': 10, 'message': 'Disassociation'},
    {'type': 0, 'subtype': 11, 'message': 'Authentication'},
    {'type': 0, 'subtype': 12, 'message': 'Deauthentication'},
    {'type': 0, 'subtype': 13, 'message': 'Action'},
    {'type': 0, 'subtype': 14, 'message': 'Action NoACK'},
    {'type': 0, 'subtype': 15, 'message': 'Reserved'},
    {'type': 1, 'subtype': 0,  'message': 'Reserved'},
    {'type': 1, 'subtype': 1,  'message': 'Reserved'},
    {'type': 1, 'subtype': 2,  'message': 'Trigger'},
    {'type': 1, 'subtype': 3,  'message': 'TACK'},
    {'type': 1, 'subtype': 4,  'message': 'Beamforming report poll'},
    {'type': 1, 'subtype': 5,  'message': 'VHT/HE NDP Announcement'},
    {'type': 1, 'subtype': 6,  'message': 'Control frame extension'},
    {'type': 1, 'subtype': 7,  'message': 'Control wrapper'},
    {'type': 1, 'subtype': 8,  'message': 'Block Ack Request (BAR)'},
    {'type': 1, 'subtype': 9,  'message': 'Block Ack (BA)'},
    {'type': 1, 'subtype': 10, 'message': 'PS-Poll'},
    {'type': 1, 'subtype': 11, 'message': 'RTS'},
    {'type': 1, 'subtype': 12, 'message': 'CTS'},
    {'type': 1, 'subtype': 13, 'message': 'ACK'},
    {'type': 1, 'subtype': 14, 'message': 'CF_End'},
    {'type': 1, 'subtype': 15, 'message': 'CF-End + CF-Ack'},
    {'type': 2, 'subtype': 0,  'message': 'Data'},
    {'type': 2, 'subtype': 1,  'message': 'Reserved'},
    {'type': 2, 'subtype': 2,  'message': 'Reserved'},
    {'type': 2, 'subtype': 3,  'message': 'Reserved'},
    {'type': 2, 'subtype': 4,  'message': 'Null (no data)'},
    {'type': 2, 'subtype': 5,  'message': 'Reserved'},
    {'type': 2, 'subtype': 6,  'message': 'Reserved'},
    {'type': 2, 'subtype': 7,  'message': 'Reserved'},
    {'type': 2, 'subtype': 8,  'message': 'QoS Data'},
    {'type': 2, 'subtype': 9,  'message': 'QoS Data + CF-Ack'},
    {'type': 2, 'subtype': 10, 'message': 'QoS Data + CF-Poll'},
    {'type': 2, 'subtype': 11, 'message': 'QoS Data + CF-Ack + CF-Poll'},
    {'type': 2, 'subtype': 12, 'message': 'QoS Null (no data)'},
    {'type': 2, 'subtype': 13, 'message': 'Reserved'},
    {'type': 2, 'subtype': 14, 'message': 'QoS CF-Poll (no data)'},
    {'type': 2, 'subtype': 15, 'message': 'QoS CF-Ack + CF-Poll (no data)'},
    {'type': 3, 'subtype': 0,  'message': 'DMG Beacon'},
    {'type': 3, 'subtype': 1,  'message': 'S1G Beacon'}
]

#   3   Extension
#   3   0   DMG Beacon
#   3   1   S1G Beacon
#   3   x   Reserved

def analyseProtocol(p):
    global prot
    global prev_msg
    if p.haslayer(Dot11):
        if ((p.addr1 == panels[0]) or (p.addr2 == panels[0])):
            if ((p.type==1) and (p.subtype==13)):
                pass  # ignore ACK's
            else:
                msg = str(p.type) + ":" + str(p.subtype)
                prot.update({msg : prev_msg})
                prev_msg = msg
            
# States according to 802.11 state machine
# State 1: Unauthenticated, Unassociated
# State 2: Authenticated, Unassociated
# State 3: Authenticated, Associated, 802.1X port blocked
# State 4: Authenticated, Associated, 802.1X port unblocked

def analysePacket(p):
    global state
    global ptime
    if p.haslayer(Dot11):
        if ((p.addr1[0:5] == '58:cf') or (p.addr1[0:5] =='68:67')):
            ptime = p.time
            if p.addr1 not in state.keys():
                state.update({p.addr1 : 1})
            elif (p.type == 0 and p.subtype == 11) and (state[p.addr1] < 2):
                state.update({p.addr1 : 2})
            elif ((p.type == 0 and p.subtype == 1) or (p.type == 0 and p.subtype == 3)) and (state[p.addr1] < 3):
                state.update({p.addr1 : 3})
            elif p.type == 0 and p.subtype == 10 and (state[p.addr1] >= 3 ):
                state.update({p.addr1 : 2})
            elif p.type == 0 and p.subtype == 12 and (state[p.addr1] >= 2 ):
                state.update({p.addr1 : 1})
            else:
                pass
        if not p.addr2 is None:
            if ((p.addr2[0:5] == '58:cf') or (p.addr2[0:5] =='68:67')):
                ptime = p.time
                if p.addr2 not in state.keys():
                    state.update({p.addr2 : 1})
                elif p.type == 0 and p.subtype == 11:
                    state.update({p.addr2 : 2})
                elif ((p.type == 0 and p.subtype == 1) or (p.type == 0 and p.subtype == 3)) and (state[p.addr2] < 3):
                    state.update({p.addr2 : 3})
                elif p.type == 0 and p.subtype == 10 and (state[p.addr2] >= 3 ):
                    state.update({p.addr2 : 2})
                elif p.type == 0 and p.subtype == 12 and (state[p.addr2] >= 2 ):
                    state.update({p.addr2 : 1})
                else:
                    pass

def showStatus():
    global state
    global ptime
    os.system('clear')
    print("Showing status at {}:".format(ptime))
    for k in state.keys():
        if state[k] == 1:
            out = "*---"
        elif state[k] == 2:
            out = "-*--"
        elif state[k] == 3:
            out = "--*-"
        elif state[k] == 4:
            out = "---*"
        print("{} : {}".format(k, out))
        

def showProtocol():
    global prot
    os.system('clear')
    for k in prot.keys():
        print("{} : {}".format(k, prot[k]))

if __name__ == "__main__":
    # os.system('ifconfig wlan0 down')
    # os.system('iwconfig wlan0 mode monitor')
    # os.system('iwconfig wlan0 channel 10')
    # os.system('ifconfig wlan0 up')
    t1 = threading.Thread(target=readPackets)
    t1.start()
    while True:
        showProtocol()
        time.sleep(1)

