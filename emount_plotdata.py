#!/usr/bin/python

import argparse
import binascii
import struct
import matplotlib.pyplot as plt
import numpy as np

parser = argparse.ArgumentParser(description='Process emount data')
parser.add_argument('--infile', dest='infile', help='input file')

args = parser.parse_args()

infile=open(args.infile,'r')

def apertureval(fstop):
    return hex(int((16.0+2*log(fstop,2))*256.0))

def valtoaperture(val):
    return 2**(val/512.0-8.0)

seen_lens = []

timespos = []
mpos1 = []
mpos2 = []
speeds_p = []
speeds_s = []
#times32 = []
#mpos32_1 = []
#mpos32_2 = []
#times34 = []
#mpos34 = []

times1D = []
pos1D = []

times1C = []
pos1C = []

times1F = []
pos1F = []

times22 = []
pos22 = []

times3C = []
pos3C = []

aperturetimes = []
apertures1 = []
apertures2 = []

aperturestattimes = []
aperturestats1 = []
aperturestats2 = []

times_cslot1 = []
types_cslot1 = []
cslot1_lens = [0x1D, 0x20]

times_cslot2 = []
types_cslot2 = []
cslot2_lens = [0x16, 0x17, 0x1a, 0x1b, 0x1e, 0x24, 0x27]

lasttime = None
lastpos_p = None
lastpos_s = None
speedp = None
speeds = None

min_pos = 99999999999999
max_pos = 0

for line in infile:
    [pktts,data] = line.split(',',1)
    pktts = float(pktts)
    [lenstr,data] = data.split(',',1)
    pktlen = int(lenstr.split(':',1)[1],16)
    payloadlen = pktlen - 8
    [ftype,snum,speed,rxtx,data] = data.split(',',4)
    rxtx = int(rxtx.split(':',1)[1])
    if hex(pktlen) not in seen_lens:
        seen_lens.append(hex(pktlen))
    pktdata = bytearray.fromhex(data.split('\"',2)[1])
    if(rxtx == 0):
        bytesproc = 0
        while(bytesproc < payloadlen):
            cmdid = pktdata[bytesproc]
            if(cmdid == 0x6):
                timespos.append(pktts)
                motorpos1 = struct.unpack('<H', pktdata[bytesproc+3:bytesproc+5])[0]
                if(motorpos1 == 0):
                    motorpos1 = None
                #This looks like a Metabones IV bug
                elif(motorpos1 == 0x7fff):
                    print "Metabones bug 1"
                    motorpos1 = None
                elif(motorpos1 == 0xa000):
                    print "Metabones bug 2"
                    motorpos1 = None
#                elif(motorpos1 == 0x01c0):
#                    print "Metabones bug 3"
#                    motorpos1 = None
                else:
                    if(motorpos1 > max_pos):
                        max_pos = motorpos1
                    if(motorpos1 < min_pos):
                        min_pos = motorpos1
                motorpos2 = struct.unpack('<H', pktdata[bytesproc+21:bytesproc+23])[0]
                if(motorpos2 == 0):
                    motorpos2 = None

                mpos1.append(motorpos1)
                mpos2.append(motorpos2)
                if(lasttime):
                    if(motorpos1 is not None):
                        speedp = (motorpos1-lastpos_p)/(pktts-lasttime)
                        lastpos_p = motorpos1
                    else:
                        speedp = None
                    if(motorpos2 is not None):
                        speeds = (motorpos2-lastpos_s)/(pktts-lasttime)
                        lastpos_s = motorpos2
                    else:
                        speeds = None
                speeds_p.append(speedp)
                speeds_s.append(speeds)
                lasttime = pktts
                if(motorpos1):
                    lastpos_p = motorpos1
                if(motorpos2):
                    lastpos_s = motorpos2
                #May actually be multiple status responses, but so far always seem to be the same order
                #but I should look for potential patterns when motorpos2 is 0
                bytesproc += 40
            elif(cmdid == 0x05):
                #This almost surely is actually multiple status responses - but the packets in this status slot are ALWAYS 0x69 bytes long
                #and so far I haven't analyzed this status packet at all
                bytesproc += 97
                aperturestattimes.append(pktts)
                #Aperture is bytes 1-2 and 3-4
                #One appears to lead the other - I'm guessing a predicted/current or current/last like motor pos
                #Possible reason for publishing "last" is to mitigate the impact of a lost response message
                (aperture1,aperture2)=struct.unpack_from('<HH', pktdata, offset=1)
                aperturestats1.append(valtoaperture(aperture1))
                aperturestats2.append(valtoaperture(aperture2))
                #Bytes 78 and 79 repeat the two bytes of the last 0x2F command
                #Strangely, 0x2F hops between the two command timeslots depending on where in the focusing phase
                #you are
            elif(cmdid == 0x1C):
                bytesproc += 2
            elif(cmdid == 0x1D):
                bytesproc += 2
            elif(cmdid == 0x1F):
                bytesproc += 2
            elif(cmdid == 0x22):
                bytesproc += 3
            elif(cmdid == 0x3C):
                bytesproc += 4
            else:
                print "Unknown response ID seen: " + hex(cmdid) + " in packet with len " + hex(pktlen)
                break
            
    else:
        bytesproc= 0
        while(bytesproc < payloadlen):
            cmdid = pktdata[bytesproc]
            if(cmdid == 0x1C):
                bytesproc += 1
                times1C.append(pktts)
                pos1C.append(lastpos_p)
            elif(cmdid == 0x1D):
                times1D.append(pktts)
                print str(pktts) + ": " + binascii.hexlify(pktdata[bytesproc:bytesproc+5])
                (positioncmd, cmdtype) = struct.unpack('<hH', pktdata[bytesproc+1:bytesproc+5])
                if(positioncmd == 0):
                    positioncmd = None
                if((cmdtype == 0x3cff) | (cmdtype == 0x400)):
                    positioncmd += lastpos_p
                elif(cmdtype == 0):
                    positioncmd *= 1
                else:
                    raise ValueError("Unknown cmd type " + hex(cmdtype) + " seen for cmdid 0x1D");
                pos1D.append(positioncmd)
                bytesproc += 5
            elif(cmdid == 0x03):
                aperturetimes.append(pktts)
                (aperture1,aperture2)=struct.unpack_from('<HH', pktdata, offset=4)
                apertures1.append(valtoaperture(aperture1))
                apertures2.append(valtoaperture(aperture2))
                bytesproc += 21
            elif(cmdid == 0x04):
                bytesproc += 14
            elif(cmdid == 0x22):
                data22 = struct.unpack('<H', pktdata[bytesproc+1:bytesproc+3])[0]
                times22.append(pktts)
                pos22.append(data22)
                bytesproc += 3
            elif(cmdid == 0x2F):
#                print str(pktts) + ": " + binascii.hexlify(pktdata[bytesproc:bytesproc+3])
                bytesproc += 3
            elif(cmdid == 0x3C):
                print str(pktts) + ": " + binascii.hexlify(pktdata[bytesproc:bytesproc+8])
                bytesproc += 8
                times3C.append(pktts)
                pos3C.append(lastpos_p)
            elif(cmdid == 0x1F):
                print str(pktts) + ": " + binascii.hexlify(pktdata[bytesproc:bytesproc+14])
                bytesproc += 14
                times1F.append(pktts)
                pos1F.append(lastpos_p)
            else:
                print "Unknown command ID seen: " + hex(cmdid)  + " in packet with len " + hex(pktlen)
                break
                    
#    if pktlen == 0x30:
#        motorpos1 = struct.unpack('<H',pktdata[3:5])[0]
#        times30.append(pktts)
#        mpos30_1.append(motorpos1)
#        if(motorpos1 > max_pos):
#            max_pos = motorpos1
#        if(motorpos1 < min_pos):
#            min_pos = motorpos1
#
#        motorpos2 = struct.unpack('<H',pktdata[21:23])[0]
#        if(motorpos2 == 0):
#            motorpos2 = None
#        mpos30_2.append(motorpos2)
#
#        if(lasttime):
#            speedp = (motorpos1-lastpos_p)/(pktts-lasttime)
#            if(motorpos2):
#                speeds = (motorpos2-lastpos_s)/(pktts-lasttime)
#            else:
#                speeds = None
#        speeds30_p.append(speedp)
#        speeds30_s.append(speeds)
#        lasttime = pktts
#        lastpos_p = motorpos1
#        lastpos_s = motorpos2
#        
#
#    if pktlen == 0x32:
#        firstcmd = pktdata[0]
#        if(firstcmd == 0x1D):
#            offset = 2
#        elif(firstcmd == 0x1C):
#            offset = 2
#        elif(firstcmd == 0x1F):
#            offset = 2
#        elif(firstcmd == 0x06):
#            offset = 0
#        else:
#            print "Saw unknown command " + hex(firstcmd)
#            break
#
#        times32.append(pktts)
#        motorpos1 = struct.unpack('<H',pktdata[offset+3:offset+5])[0]
#        if(motorpos1 == 0):
#            motorpos1 = None
#        mpos32_1.append(motorpos1)
#        motorpos2 = struct.unpack('<H',pktdata[offset+21:offset+23])[0]
#        if(motorpos2 == 0):
#            motorpos2 = None
#        mpos32_2.append(motorpos2)
#    if pktlen == 0x34:
#        firstcmd = pktdata[0]
#        if(firstcmd == 0x3C):
#            offset = 4
#        elif(firstcmd == 0x06):
#            offset = 0
#        else:
#            print "Saw unknown command " + hex(firstcmd)
#            break
#        motorpos1 = struct.unpack('<H',pktdata[offset+3:offset+5])[0]
#        if(motorpos1 == 0):
#            motorpos1 = None        
#        times34.append(pktts)
#        mpos34.append(motorpos1)
#
               
    if pktlen in cslot1_lens:
        times_cslot1.append(pktts)
        types_cslot1.append(cslot1_lens.index(pktlen))

    if pktlen in cslot2_lens:
        times_cslot2.append(pktts)
        types_cslot2.append(cslot2_lens.index(pktlen))
        
seen_lens.sort()

print seen_lens

#print motordata
plt.figure(1)
plt1 = plt.subplot(211)
plt1.plot(timespos,mpos1,'b',timespos,mpos2,'r')
plt1.plot(times1D,pos1D,'co', times1C, pos1C, 'rx')
plt1.plot(times1F,pos1F,'y^',times3C,pos3C,'g^',times22,pos22,'b^')
types_cslot2 = np.array(types_cslot2)
#plt.vlines(times_cslot2,18000+types_cslot2*250,18250+types_cslot2*250)
#plt.axis([6.2,7.2,18500,19500])

plt2 = plt.subplot(212,sharex=plt1)
plt2.plot(timespos,speeds_p,'b',timespos,speeds_s,'r')
plt2.axhline(color='k')

#plt3 = plt.subplot(313,sharex=plt1)
#plt3.semilogy(aperturetimes,apertures1,'b',aperturetimes,apertures2,'r')
#plt3.semilogy(aperturestattimes,aperturestats1,'c',aperturestattimes,aperturestats2,'g')
#plt3.axis([None,None,-0.5,6.5])
#plt.axis([6.2,7.2,-0.5,6.5])

#plt.subplot(313)
#plt.plot(times_cslot1,types_cslot1,'m*')
#plt.axis([None,None,-0.2,1.2])

print("Min position: " + str(min_pos) + ", max position: " + str(max_pos))
plt.show()
infile.close()


