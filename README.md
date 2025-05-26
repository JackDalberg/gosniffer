# Gosniffer

Rewrite of RealmShark (RotMG packet sniffer-parser) in Go. Currently finds the device which speaks with RotMG and nothing else.  Need to add:
- Packet decryption
- Packet typing and parsing
- Parsed packet API to allow for aggregation of packet data in meaningful ways (DPS logger, loot tracker, ...)
