#!/bin/bash

DEVICEID_CA_DIR=./deviceid-embedded-ca
ROLLBACKS="index.txt index.txt.attr serial"

for FILE in $ROLLBACKS
do
    if [ -e $DEVICEID_CA_DIR/$FILE.old ]; then
	mv $DEVICEID_CA_DIR/$FILE.old $DEVICEID_CA_DIR/$FILE
    else
        >&2 echo "Cannot rollback $FILE"
    fi
done

SERIAL=$(cat $DEVICEID_CA_DIR/serial)
if [ -e $DEVICEID_CA_DIR/newcerts/$SERIAL.pem ]; then
    rm $DEVICEID_CA_DIR/newcerts/$SERIAL.pem
else
    >&2 echo "No certs to remove."
fi
