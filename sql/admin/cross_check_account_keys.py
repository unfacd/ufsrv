#!/usr/bin/python

#distinc users in keys table
# select count(distinct number) from `keys`;

#distinct use with count keys for each
#select number,count(distinct public_key) from `keys` group by number;

#total number of key
#select sum(cnt) TotalKeys from (select number,count(distinct public_key) cnt from `keys` group by number) d;

#---------------------
#
# select id,hex(ufsrvuid),count(distinct number) from `accounts` group by id;


import MySQLdb
import base32_crockford #https://github.com/jbittel/base32-crockford

db = MySQLdb.connect("localhost", "root", "$6$VtJOS4Z6WLlqwx1$r7MJoDgl.uucPIDxbuZD4vbySuJpAo4WqvfsRWl6/BcKUUzE/fJXX13cqznfrd68l.ugn7Ad4XhGoiiThDbnV/","ufsrv" )
cursor = db.cursor()

sql = "SELECT id, HEX(ufsrvuid), JSON_UNQUOTE(JSON_EXTRACT(data, '$.number')), count(distinct number) FROM accounts GROUP BY id"

try:
    try:
        cursor.execute(sql)
    except (MySQLdb.Error, MySQLdb.Warning) as e:
        print(e)

    try:
        results = cursor.fetchall()
        for row in results:
            rid         = row[0]
            ufsrvuid    = base32_crockford.encode(int(row[1], 16))
            count       = row[3]
            username    = row[2]
            print "id=%d, ufsrvuid=%s, number=%s, count=%d" % \
                    (rid, ufsrvuid, username, count)

    except TypeError as e:
            print(e)

finally:
    cursor.close
    db.close()
