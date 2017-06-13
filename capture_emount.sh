#!/bin/sh
sigrok-cli -d fx2lafw -c samplerate=6M --continuous -C D0=BODY_VD_LENS,D1=VCC,D2=LENS_CS_BODY,D3=RXD,D4=TXD,D5=BODY_CS_LENS -t VCC=1 -w -O srzip -o $1
