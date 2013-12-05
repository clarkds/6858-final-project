#!/bin/bash

rm -r db
rm -r users/*
python serverdb.py init-publickey
python serverdb.py init-permissions
