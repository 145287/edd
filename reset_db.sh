#!/bin/bash
# Removes and re-creates the local edddjango database from the the production (non-django) database

# Terminate early if any subsequent command fails
set -e

# Confirm before dropping the local database
echo "This script removes and re-creates the local EDD database (edddjango)"
read -p "Are you sure you want to lose all the data? " CONFIRMATION

while [[ ! $CONFIRMATION =~ ^yes|Yes|YES|no|No|NO$ ]]
do
	echo 'Do you want to drop the local EDD database? ("yes" or "no"): '
	read CONFIRMATION
done

# Exit if user refused to drop database
if [[ $CONFIRMATION =~ ^no|No|NO$ ]]
then
	exit 0
fi

read -p "Developer's EDD Username (LDAP): " EDD_USERNAME

# detect presence of the dump file & prompt before overwriting
CREATE_DUMP_FILE=false
DUMP_FILE_NAME=edddb.sql
if [ ! -f edddb.sql ] 
then
	echo "File $DUMP_FILE_NAME wasn't found."
	SET CREATE_DUMP_FILE=true
else
	MODDATE=$(ls -lT $DUMP_FILE_NAME | perl -pe 's/^.*\s+([a-zA-z]+\s+\d\d\s+\S+.*)$DUMP_FILE_NAME$/$1/g')
	echo "Found existing dump file $DUMP_FILE_NAME."
	read -p "Do you want to use the existing dump file, last modified at $MODDATE (yes/no)? " REPLY
	
	
	if [[ $REPLY =~ ^no|No|NO$ ]]
	then
		CREATE_DUMP_FILE=true
	else
		echo "Using existing dump file."
	fi
fi

# (Re)create the dump file if chosen in logic above
if [ $CREATE_DUMP_FILE == true ]
then
	echo "Creating SQL dump file eddddb.sql... Enter production edduser password below."
	pg_dump -i -h postgres.jbei.org -U edduser -F p -b -v -f edddb.sql edddb
fi

echo "*************************************************************"
echo "Dropping database edddjango..."
echo "*************************************************************"
psql postgres -c 'DROP DATABASE IF EXISTS edddjango'

echo "*************************************************************"
echo "Re-creating database edddjango..."
echo "*************************************************************"
psql postgres -c 'CREATE DATABASE edddjango'
psql -d edddjango -c 'CREATE SCHEMA old_edd;'
psql -d edddjango -c 'GRANT ALL ON SCHEMA old_edd TO edduser;'

echo "*************************************************************"
echo "Replacing schema name in the dump file..."
echo "*************************************************************"

cat edddb.sql | sed 's#SET search_path = #SET search_path = old_edd, #g' | \
sed 's#public\.#old_edd\.#g' | sed 's#Schema: public;#Schema: old_edd;#g' > edddb_upd.sql

echo "*************************************************************"
echo "Loading dump file into the database..."
echo "*************************************************************"
psql edddjango < edddb_upd.sql


echo "*************************************************************"
echo "Running Django migrations..."
echo "*************************************************************"
./manage.py migrate

echo "*************************************************************"
echo "Performing conversion..."
echo "*************************************************************"
psql edddjango < convert.sql

echo "*************************************************************"
echo "Escalating privileges for EDD user $EDD_USERNAME"
echo "*************************************************************"
psql edddjango -c "update auth_user set is_superuser=true, is_staff=true where username ='$EDD_USERNAME'" 

echo "Done."