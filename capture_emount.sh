#!/bin/sh
sigrok-cli -d fx2lafw -c samplerate=6M --continuous -C 0=BODY_VD_LENS,1=VCC,2=LENS_CS_BODY,3=RXD,4=TXD,5=BODY_CS_LENS -t VCC=1 -w -O srzip -o $1
