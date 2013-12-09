#!/bin/bash

rm -r db
rm -r users
mkdir users
python db.py init-publickey
python db.py init-permission
python db.py init-password
python server.py
