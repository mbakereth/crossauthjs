#!/bin/bash
havedotenv=`which dotenv`
if [ "$havedotenv" != "" ]; then
	dotenv $*
fi

