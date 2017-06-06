#!/bin/sh
sigrok-cli -i $1 -P sony_emount:rx_cs=LENS_CS_BODY:rx=RXD:tx=TXD:tx_cs=BODY_CS_LENS
