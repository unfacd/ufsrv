#!/usr/bin/python
#Invoke:
# ./ufsrvdb_add_userdata.py -u 438 -k unsolicited_contact -v 1 -o replace
# ./ufsrvdb_add_userdata.py -k unsolicited_contact -v 0 -o insert
#
#
#distinc users in keys table
# select count(distinct number) from `keys`;

#distinct use with count keys for each
#select number,count(distinct public_key) from `keys` group by number;

#total number of key
#select sum(cnt) TotalKeys from (select number,count(distinct public_key) cnt from `keys` group by number) d;

#all orphan rows in `key` (dont have corresponding ufrsvuid in `accounts`)
#SELECT distinct(number) FROM `keys` WHERE number NOT IN (SELECT ULID_ENCODE(ufsrvuid) as ufsrvuid FROM accounts);
#with count of each
#SELECT number,count(distinct public_key) FROM `keys` WHERE number NOT IN (SELECT ULID_ENCODE(ufsrvuid) as ufsrvuid FROM accounts) group by number;
#---------------------
#
# select id,hex(ufsrvuid),count(distinct number) from `accounts` group by id;
'''

'''
import sys, getopt
import MySQLdb
from beautifultable import BeautifulTable
#python -m pip install beautifultable

def setup_db():
    db = MySQLdb.connect("localhost", "root", "$6$VtJOS4Z6WLlqwx1$r7MJoDgl.uucPIDxbuZD4vbySuJpAo4WqvfsRWl6/BcKUUzE/fJXX13cqznfrd68l.ugn7Ad4XhGoiiThDbnV/","ufsrv" )
    cursor = db.cursor()
    return db, cursor



def main(argv):
    sequence_id = key = value = ''
    op = 'insert'
    try:
        try:
            opts, args = getopt.getopt(argv,"hu:k:v:o:",["help=", "sequence_id=","key=", "value=", "op="])
        except getopt.GetoptError:
            print 'cm -u <uid> -k <key> -v <value> [-o <insert|replace>]'
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                print 'cm -u <uid> -k <key> -v <value> [-o <insert|replace>]'
                print './ufsrvdb_add_userdata.py -u 438 -k unsolicited_contact -v 0 -o replace'
                print 'If u is missing, command performed on all records'
                sys.exit()
            elif opt in ("-u", "--sequence_id"):
                sequence_id = arg
            elif opt in ("-k", "--key"):
                key = arg
            elif opt in ("-v", "--value"):
                value = arg
            elif opt in ("-o", "--op"):
                op = arg

        if key=='' or value=='':
            sys.exit()

        if (op != 'replace' and op != 'insert'):
            print 'op must be insert or replace'
            sys.exit()

        db, cursor = setup_db()
        sql_select = "SELECT id, ULID_ENCODE(ufsrvuid) as ufsrvuid, JSON_UNQUOTE(JSON_EXTRACT(data, '$.number')) as username FROM accounts GROUP BY id"
        sql_insert_s = "UPDATE accounts SET data_user = JSON_%s(data_user, '$.%s', '%s') WHERE id=%s"
        sql_insert_i = "UPDATE accounts SET data_user = JSON_%s(data_user, '$.%s', %s) WHERE id=%s"
        sql_insert   =  sql_insert_i

        table = BeautifulTable()
        table.column_headers = ["id", "ufsrvuid", "username"]

        if (sequence_id):
            print ("Processing sequence_id:'%s' with key: '%s', value: '%s'") % (sequence_id, key, value)
            cmd = sql_insert % ('INSERT' if op=='insert' else 'REPLACE', key, value, sequence_id)
            print (cmd)
            try:
                cursor.execute(cmd)
                db.commit()
            except TypeError as e:
                print(e)
        else:
            try:
                cursor.execute(sql_select)
            except (MySQLdb.Error, MySQLdb.Warning) as e:
                print(e)

            try:
                results = cursor.fetchall()
                for row in results:
                    rid         = row[0]
                    ufsrvuid    = row[1]
                    username    = row[2]
                    #table.append_row([rid, ufsrvuid, username])
                    print ("Processing sequence_id:'%s' -> '%s' with uid: '%s', key: '%s', value: '%s'") % (rid, ufsrvuid, sequence_id, key, value)
                    cmd = sql_insert % ('INSERT' if op=='insert' else 'REPLACE', key, value, sequence_id)
                    print (cmd)
                    cursor.execute(cmd)
                db.commit()
            except TypeError as e:
                print(e)

    finally:
        cursor.close
        db.close()

if __name__ == "__main__":
    main(sys.argv[1:])
