#!/usr/bin/python

#distinc users in keys table
# select count(distinct number) from `keys`;

#distinct use with count keys for each
#select number,count(distinct public_key) from `keys` group by number;

#total number of key
#select sum(cnt) TotalKeys from (select number,count(distinct public_key) cnt from `keys` group by number) d;

#all orphan rows in `key` (dont have corresponding ufrsvuid in `accounts`)
#SELECT distinct(number) FROM `keys` WHERE number NOT IN (SELECT ULID_ENCODE(ufsrvuid) as ufsrvuid FROM accounts);
#with count of each prekey per user
#SELECT number, COUNT(distinct public_key) FROM `keys` WHERE number NOT IN (SELECT ULID_ENCODE(ufsrvuid) as ufsrvuid FROM accounts) group by number;
#Total number of orphan prekey records (to verify count manually the out from the command above)
#select sum(cnt) TotalKeys from (SELECT number, count(distinct public_key) cnt FROM `keys` WHERE number NOT IN (SELECT ULID_ENCODE(ufsrvuid) as ufsrvuid FROM accounts))d
#---------------------
#
# select id,hex(ufsrvuid),count(distinct number) from `accounts` group by id;


import MySQLdb
import base32_crockford #https://github.com/jbittel/base32-crockford
from beautifultable import BeautifulTable
#python -m pip install beautifultable

db = MySQLdb.connect("localhost", "root", "$6$VtJOS4Z6WLlqwx1$r7MJoDgl.uucPIDxbuZD4vbySuJpAo4WqvfsRWl6/BcKUUzE/fJXX13cqznfrd68l.ugn7Ad4XhGoiiThDbnV/","ufsrv" )
cursor = db.cursor()

table = BeautifulTable()
table.column_headers = ["id", "ufsrvuid", "username", "count"]

username = raw_input("Type username: ")  
sql_userexists = "SELECT id FROM accounts where ULID_ENCODE(ufsrvuid)='%s'" % \
 (username)
sql_records_count = "SELECT count(*) FROM `keys` WHERE number IN (SELECT ULID_ENCODE(ufsrvuid) as ufsrvuid FROM accounts where ULID_ENCODE(ufsrvuid)='%s')" % \
 (username)
sql_delete = "DELETE FROM `keys` WHERE number IN (SELECT ULID_ENCODE(ufsrvuid) FROM accounts where ULID_ENCODE(ufsrvuid)='%s')"

try:
    try:
     cursor.execute(sql_userexists)
    except (MySQLdb.Error, MySQLdb.Warning) as e:
     print(e)
     return None
    try:
     sequence_id = cursor.fetchone()
     print ("User exists with sequence id: '%d'") % sequence_id
    except TypeError as e:
     print(e)
     return None
     
    try:
     cursor.execute(sql_records_count)
    except TypeError as e:
     print(e)
     return None
    try:
     records_count = cursor.fetchone()
     print "Number of affected records: '%d'" % records_count
    except TypeError as e:
     print(e)  

finally:
 cursor.close
 db.close()

