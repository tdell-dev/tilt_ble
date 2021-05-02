#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This file deals with the Tilt formatted message
from struct import unpack
import json
import aioblescan as aios
#Tilt format based on iBeacon format and filter includes Apple iBeacon identifier portion (4c000215) as well as Tilt specific uuid preamble (a495)
TILT = '4c000215a495'


class Tilt(object):
    """
    Class defining the content of a Tilt advertisement
    """

    def decode(self, packet):
        data = {}
        raw_data = packet.retrieve('Payload for mfg_specific_data')
        if raw_data:
            pckt = raw_data[0].val
            payload = raw_data[0].val.hex()
            mfg_id = payload[0:12]
            rssi = packet.retrieve('rssi')
            mac = packet.retrieve("peer")
            if mfg_id == TILT:
                data['uuid'] = payload[8:40]
                data['major'] = unpack('>H', pckt[20:22])[0] #temperature in degrees F
                data['minor'] = unpack('>H', pckt[22:24])[0] #specific gravity x1000
                data['tx_power'] = unpack('>b', pckt[24:25])[0] #weeks since battery change (0-152 when converted to unsigned 8 bit integer) and other TBD operation codes
                data['rssi'] = rssi[-1].val
                data['mac'] = mac[-1].val
                return json.dumps(data)