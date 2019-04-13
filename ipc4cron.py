#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' ipc4cron - IP collector cronjob
             * Query an updated list of IP ranges from iTop.
             * Scan this IP ranges for changes.
             * Updates the iTop database.
             * CleanUp old log files.


    This program is part of the Scan2 Suite.
    https://github.com/dweKNOWLEDGEisFREE

    This program is licensed under the GNU General Public License v3.0

    Copyright 2019 by David Weyand, Ernst Schmid

'''


# IMPORTS
import sys, os, json, requests, datetime, mysql.connector
import ipc4lib
from alembic.util.messaging import status
#from pid import PidFile

# VERSION
__all__     = []
__version__ = 0.4
__date__    = '2018-06-01'
__updated__ = '2018-07-26'

# CONFIGURATION DATA
cfg_file = 'config.json'
log_file = 'cron_log.json'
inf_file = 'cron_inf.json'

# PATH SETTINGS
# Path settings
path_XML  = './data/logfiles'
path_HTML = './static/data/logfiles'


''' Database: Requesting ORG LIST
'''
def dbAccessORG (host, database, user, password):
    access_data = {'host': host, 'database': database, 'user': user, 'password': password}
    # Result list
    res=[]
    try:
        print('ipc4scan: connect')
        cnx = mysql.connector.connect(**access_data)
        cursor = cnx.cursor()
        print('ipc4scan: query')
        query = ("SELECT DISTINCT org_id FROM jobs ORDER BY org_id")
        cursor.execute(query)
    #   print('res:'+str(cursor))
        for (org_id) in cursor:
            res.append([org_id])
        #   print("ipc4scan: ORG ID = "+str(id))
        cursor.close()
    except mysql.connector.Error as err:
        print(cursor.statement, file=sys.stderr)
        print(err, file=sys.stderr)
    else:
        print('ipc4scan: close')
        cnx.close()
    return res


''' Database: CleanUp of old HOST entries
'''
def dbCleanUp (host, database, user, password):
    access_data = {'host': host, 'database': database, 'user': user, 'password': password}
    # Result list
    try:
        print('ipc4scan: connect')
        cnx = mysql.connector.connect(**access_data)
        cursor = cnx.cursor()
        print('ipc4scan: delete')
        sqlcmd = ("DELETE FROM hosts WHERE (TO_SECONDS(now())-TO_SECONDS(ts_new))>86400")
        cursor.execute(sqlcmd)
        cursor.close()
        cnx.commit()
    except mysql.connector.Error as err:
        print(cursor.statement, file=sys.stderr)
        print(err, file=sys.stderr)
    else:
        print('ipc4scan: close')
        cnx.close()
    return


''' Database, iTop: Requesting all currently IP ranges in use from iTop.
'''
def iTopQuery (host, database, user, password):
    access_data = {'host': host, 'database': database, 'user': user, 'password': password}
    # REST
    try:
        # REST REQUEST CREATE
        json_data = {
            'operation': 'core/get',
            'class'    : 'IPv4Range',
            'key'      : "SELECT IPv4Range"
        }
        encoded_data = json.dumps(json_data)
        # REST REQUEST TRANSMITT
        res = requests.post(cfg_itop_cr.get('url')+'/webservices/rest.php?version=1.0',
                            verify=False,
                            data={'auth_user': cfg_itop_cr.get('usr'), 
                                  'auth_pwd': cfg_itop_cr.get('pwd'),
                                  'json_data': encoded_data})
    except:
        print('ERROR...: iTop REST ACCESS FAILED', file=sys.stderr)    
    # DATABASE TRANSFER
    result = json.loads(res.text);
    if result['code'] == 0:
        # Transfer data into SQL-DB
        try:
            print('icp4cron: SQL connect')
            # open connection
            cnx = mysql.connector.connect(**cfg_mysql_cr)
            cursor = cnx.cursor()
            # delete old entries
            cmd=("""DELETE FROM jobs""")
            cursor.execute(cmd)
            # write data
            for i in result['objects'].keys():
                cmd=("""INSERT INTO jobs(firstip,lastip,org_id,org_name) VALUES (%s,%s,%s,%s)""")
                cursor.execute(cmd, (result['objects'][i]['fields']['firstip'],
                                     result['objects'][i]['fields']['lastip'], 
                                     result['objects'][i]['fields']['org_id'], 
                                     result['objects'][i]['fields']['org_name']))
            # close connection                    
            cursor.close()
            cnx.commit()
        except mysql.connector.Error as err:
            print(cursor.statement, file=sys.stderr)
            print(err, file=sys.stderr)
            cnx.rollback()
        else:
            print('icp4cron: SQL close')
            cnx.close()
    return



''' GO
'''
if __name__ == "__main__":
    # SHOW PARAMETERS
    print('ipc4cron: #['+str(len(sys.argv))+'] ['+str(sys.argv)+']')
    # SHOW PATH
    print('ipc4cron: Path - ',sys.argv[0])
    dirname, filename = os.path.split(os.path.abspath(sys.argv[0]))
    print ("ipc4cron: running from - ", dirname)
    os.chdir(dirname)

    # SHOW USER ID
    print('ipc4cron: Real UserID - %d' % os.getuid())
    print('ipc4cron: Effective UserID - %d' % os.geteuid())
    
    # READ CONFIG
    try:
        with open(cfg_file) as json_file:
            data=json.load(json_file)
    except:
        exit(1)
    
    # SAVE CONFIG DATA
    cfg_itop_cr =data['iTop'   ][0]
    cfg_mysql_cr=data['mySQL'  ][0]
    cfg_crontab =data['Crontab'][0]
    cfg_nmap    =data['Nmap'   ][0]
    cfg_logfile =data['LogFile'][0]
                
    # CHECKING CONFIG - iTop PARAMETERS
    if cfg_itop_cr ==None:
        exit(10)
    # CHECKING CONFIG - DATABASE ACCESS
    if cfg_mysql_cr ==None:
        exit(20)
    if cfg_mysql_cr['host'    ]==None or len(cfg_mysql_cr['host'    ])==0:
        exit(21)
    if cfg_mysql_cr['database']==None or len(cfg_mysql_cr['database'])==0:
        exit(22)
    if cfg_mysql_cr['user'    ]==None or len(cfg_mysql_cr['user'    ])==0:
        exit(23)
    if cfg_mysql_cr['password']==None or len(cfg_mysql_cr['password'])==0:
        exit(24)
    # CHECKING CONFIG - CRONTAB ACTION FLAGS
    if cfg_crontab ==None:
        exit(30)
    if cfg_crontab['doQuery' ]==None:
        exit(31)
    if cfg_crontab['doScan'  ]==None:
        exit(32)
    if cfg_crontab['doUpdate']==None:
        exit(33)
    if cfg_crontab['doClean' ]==None:
        exit(34)
    # CHECKING CONFIG - Nmap PARAMETERS
    if cfg_nmap ==None:
        exit(40)
    # CHECKING CONFIG - LOGFILES
    if cfg_logfile['number']==None or int(cfg_logfile['number'])==0:
        exit(50)
    if cfg_logfile['age'   ]==None or int(cfg_logfile['age'   ])==0:
        exit(51)

    # TIMESTAMP
    tst='{:%Y-%m-%d--%H-%M-%S}'.format(datetime.datetime.now())
    print('ipc4cron: START TIME STAMP ',tst) 
    # UPDATE status
    json_inf={"tst_st":tst, "tst_sp":'', "status":'RUNNING'}
    with open(inf_file, 'w') as outfile:
        json.dump(json_inf, outfile)



    if cfg_crontab['doQuery']==True:
        # Info
        print('ipc4cron: Requesting IP ranges from iTop.', file=sys.stdout)
        # Starting process
        iTopQuery(**cfg_mysql_cr)

    
    if cfg_crontab['doScan']==True:
        # Info
        print('ipc4cron: Scanning IP ranges.', file=sys.stdout)
        # IP Address cleanup
        print('ipc4cron: Dropping old IP address entries.', file=sys.stdout)
        dbCleanUp(**cfg_mysql_cr)
        # Retrieve list of ORG_IDs
        if len(sys.argv)>1:
            lst_org=[]
            for dat in sys.argv[1].split(' '):
                lst_org.append([(dat,)])
        else:
            lst_org=dbAccessORG(**cfg_mysql_cr)
        # Process ORG_IDs
        for obj_org in lst_org:
            # Prepare ... org_id, fn
            org_id=str(obj_org[0][0])
            fn=tst+'--'+org_id
            # Generate additional parameters
            para='-id '+org_id
            if cfg_nmap['parameter'] !=None and len(cfg_nmap['parameter'])>0:
                para+=' -on "'+cfg_nmap['parameter']+'"'
            # Info ...
            print ('ipc4cron: scan ORG_ID '+org_id)
            # UPDATE status
            json_inf={"tst_st":tst, "tst_sp":'', "status":'SCANNING ORG ID '+org_id}
            with open(inf_file, 'w') as outfile:
                json.dump(json_inf, outfile)
            # BUILD SCAN COMMAND
            cmd=('./ipc4scan.py '+para+
                 ' -s "'+cfg_mysql_cr['host']+'"'+
                 ' -d "'+cfg_mysql_cr['database']+'"'+
                 ' -u "'+cfg_mysql_cr['user']+'"'+
                 ' -p "'+cfg_mysql_cr['password']+'"'+
                 ' -fx ./data/logfiles/'+fn+'.xml'+
                 ' -fh ./static/data/logfiles/'+fn+'.html')
            print ('ipc4cron: SCAN CMD ',cmd)
            sys.stdout.flush()
            sys.stderr.flush()
            os.system(cmd)
            # BUILD IMPORT COMMAND
            cmd=('./ipc4job.py -i '+org_id+
                 ' -s "'+cfg_mysql_cr['host']+'"'+
                 ' -d "'+cfg_mysql_cr['database']+'"'+
                 ' -u "'+cfg_mysql_cr['user']+'"'+
                 ' -p "'+cfg_mysql_cr['password']+'"'+
                 ' -x ./data/logfiles/'+fn+'.xml')
            print ('ipc4cron: IMPORT ',cmd)
            sys.stdout.flush()
            sys.stderr.flush()
            os.system(cmd)
    

    if cfg_crontab['doUpdate']==True:
        # Info
        print('ipc4cron: Updating iTop IP address database.', file=sys.stdout)
        # iTop Update
        # BUILD UPDATE COMMAND
        cmd=('cd itop;php exec.php')
        sys.stdout.flush()
        sys.stderr.flush()
        os.system(cmd)

        
    if cfg_crontab['doClean']==True:
        # Info
        print('ipc4cron: Removing outdated log files.', file=sys.stdout)
        # Get current time and date.
        now=datetime.datetime.today()
        # CleanUp of HTML Log File Directory
        ipc4lib.delOldLogFiles(now, path_HTML, 'html', cfg_logfile['number'], cfg_logfile['age'])
        # CleanUp of XML Log File Directory
        ipc4lib.delOldLogFiles(now, path_XML,  'xml', cfg_logfile['number'], cfg_logfile['age'])



    # TIMESTAMP
    tnd='{:%Y-%m-%d--%H-%M-%S}'.format(datetime.datetime.now())
    print('ipc4cron: STOP TIME STAMP ',tnd) 
    # UPDATE status
    json_inf={"tst_st":tst, "tst_sp":tnd, "status":'STAND BY'}
    with open(inf_file, 'w') as outfile:
        json.dump(json_inf, outfile)
    
    # UPDATE TIME MARKER
    json_log={}
    json_log['cur']=[]
    json_log['cur'].append(tst+' [UID:'+str(os.getuid()).__str__()+'/EUID:'+str(os.geteuid())+']')
    json_log['lst']=[]
    try:
        with open(log_file) as json_file:
            data=json.load(json_file)
            json_log['lst'].append(data['cur'][0])
    except:
        json_log['lst'].append("")
    with open(log_file, 'w') as outfile:
        json.dump(json_log, outfile)

    # READY
    exit(0)
