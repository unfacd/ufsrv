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
import redis
import base32_crockford #https://github.com/jbittel/base32-crockford
import json
from beautifultable import BeautifulTable
from colorama import Fore, Back, Style, init

#python -m pip install beautifultable
#python -m pip install colorama

redis_host = "10.1.64.1"
redis_host_fence = "10.1.72.1"
redis_host_msg = "10.1.80.1"
redis_port = 6379
redis_password = ""

def check_redis(sequence_id):
    try:
        cmd = 'UID:%d' % (sequence_id[0],)
        print (cmd)
        msg = r.hgetall(cmd)
        #parsed = json.loads(msg)
        #print(json.dumps(parsed, indent=2, sort_keys=True))
        print(msg)

    except Exception as e:
        print(e)

def redis_print_groups(sequence_id):
    try:
        cmd = 'ZRANGE UF:%d 0 -1' % (sequence_id[0],)
        print (Fore.RED + cmd)
        msg = r.execute_command(cmd)
        print (Fore.RED + 'User member of %d fences' % len(msg))
        print (' '.join(msg))
        for key in msg:
            print(Fore.RED + '-> Members in fence: ' + key.split(':', 1)[0])
            msg = r.execute_command('ZRANGE MEMBER_USERS_FOR_FENCE:%s 0 -1' % key.split(':', 1)[0])
            print(msg)

        cmd = 'ZRANGE INVITED_FENCES_FOR_USER:%d 0 -1' % (sequence_id[0],)
        print (Fore.GREEN + cmd)
        msg = r.execute_command(cmd)
        print (Fore.GREEN + 'User invited to %d fences' % len(msg))
        print (' '.join(msg))
        for key in msg:
            fid = key.split(':', 1)[0]
            redis_fence_invited_members(fid)
            print(Fore.GREEN + '-> Members in fence: %s (%s)') % (fid,  redis_fence_cname(fid))
            msg = r.execute_command('ZRANGE MEMBER_USERS_FOR_FENCE:%s 0 -1' % fid)
            print(msg)

        cmd = 'ZRANGE MY_INVITED_USERS:%d 0 -1' % (sequence_id[0],)
        print (Fore.YELLOW + cmd)
        msg = r.execute_command(cmd)
        print (msg)

    except Exception as e:
        print(e)

def redis_fence_cname(fid):
    try:
        cmd = 'HGET BID:%s cname' % fid
        msg = r_fence.execute_command(cmd)
        return msg
    except Exception as e:
        print(e)

def redis_fence_owner(fid):
    try:
        cmd = 'HGET BID:%s uid' % fid
        msg = r_fence.execute_command(cmd)
        return msg
    except Exception as e:
        print(e)

def redis_fence_invited_members(fid):
    try:
        cmd = 'ZRANGE INVITED_USERS_FOR_FENCE:%s 0 -1' %fid
        msg = r.execute_command(cmd)
        print (Fore.GREEN + 'Checking number of invited members (%d) in fence' % len(msg))
        print (Fore.CYAN + cmd)
        print (Fore.GREEN + ' '.join(msg))
        return msg
    except Exception as e:
        print(e)

#ZRANGE SHL_0:305 0 -1
init(autoreset=True)

db = MySQLdb.connect("localhost", "root", "$6$VtJOS4Z6WLlqwx1$r7MJoDgl.uucPIDxbuZD4vbySuJpAo4WqvfsRWl6/BcKUUzE/fJXX13cqznfrd68l.ugn7Ad4XhGoiiThDbnV/","ufsrv" )
cursor = db.cursor()

table = BeautifulTable()
table.column_headers = ["id", "ufsrvuid", "username", "count"]

username = raw_input("Type username (ufsrvuid encoded): ")
sql_userexists = "SELECT id FROM accounts where ULID_ENCODE(ufsrvuid)='%s'" % \
                 (username)
sql_records_count = "SELECT count(*) FROM `keys` WHERE number IN (SELECT ULID_ENCODE(ufsrvuid) as ufsrvuid FROM accounts where ULID_ENCODE(ufsrvuid)='%s')" % \
                    (username)
sql_delete = "DELETE FROM `keys` WHERE number IN (SELECT ULID_ENCODE(ufsrvuid) FROM accounts where ULID_ENCODE(ufsrvuid)='%s')"

# The decode_repsonses flag here directs the client to convert the responses from Redis into Python strings
# using the default encoding utf-8.  This is client specific.
r = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password)#, decode_responses=True)
r_fence = redis.StrictRedis(host=redis_host_fence, port=redis_port, password=redis_password)
r_msg = redis.StrictRedis(host=redis_host_msg, port=redis_port, password=redis_password)

try:
    try:
        cursor.execute(sql_userexists)
    except (MySQLdb.Error, MySQLdb.Warning) as e:
        print(e)
    try:
        sequence_id = cursor.fetchone()
        print ("User exists with sequence id: '%d'") % sequence_id
    except TypeError as e:
        print(e)

    try:
        cursor.execute(sql_records_count)
    except TypeError as e:
        print(e)
    try:
        records_count = cursor.fetchone()
        print "Number of affected records: '%d'" % records_count
    except TypeError as e:
        print(e)

finally:
    cursor.close
    db.close()
    check_redis(sequence_id)
    redis_print_groups(sequence_id)
