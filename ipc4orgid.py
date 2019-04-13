#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' ipc4orgid - IP collector web tool function IP SCAN
              * Scan this IP ranges for changes.


    This program is part of the Scan2 Suite.
    https://github.com/dweKNOWLEDGEisFREE

    This program is licensed under the GNU General Public License v3.0

    Copyright 2019 by David Weyand, Ernst Schmid

'''


# IMPORTS
import sys, os, json, datetime, mysql.connector
from alembic.util.messaging import status
#from pid import PidFile

# VERSION
__all__     = []
__version__ = 0.3
__date__    = '2018-06-01'
__updated__ = '2018-07-17'

# CONFIGURATION
cfg_file = 'config.json'
log_file = 'cron_log.json'
inf_file = 'cron_inf.json'


''' Database: Requesting ORG LIST
'''
def dbAccessORG (host, database, user, password):
    access_data = {'host': host, 'database': database, 'user': user, 'password': password}
    # Result list
    res=[]
    try:
        print('dbAccessORG: connect')
        cnx = mysql.connector.connect(**access_data)
        cursor = cnx.cursor()
        print('dbAccessORG: query')
        query = ("SELECT DISTINCT org_id FROM jobs ORDER BY org_id")
        cursor.execute(query)
    #   print('res:'+str(cursor))
        for (org_id) in cursor:
            res.append([org_id])
        #   print("dbAccessORG: ORG ID = "+str(id))
        cursor.close()
    except mysql.connector.Error as err:
        print(cursor.statement)
        print(err)
    else:
        print('dbAccessORG: close')
        cnx.close()
    return res



''' GO
'''
if __name__ == "__main__":
    # SHOW PARAMETERS
    print('ipc4orgid: #['+str(len(sys.argv))+'] ['+str(sys.argv)+']')
    # SHOW PATH
    print('ipc4orgid: Path - ',sys.argv[0])
    dirname, filename = os.path.split(os.path.abspath(sys.argv[0]))
    print ("ipc4orgid: running from - ", dirname)
    os.chdir(dirname)

    # SHOW USER ID
    print('ipc4orgid: Real UserID - %d' % os.getuid())
    print('ipc4orgid: Effective UserID - %d' % os.geteuid())
    
    # READ CONFIG
    try:
        with open(cfg_file) as json_file:
            data=json.load(json_file)
    except:
        exit(1)
    
    # SAVE CONFIG DATA
    cfg_mysql_cr=data['mySQL'  ][0]
    cfg_nmap    =data['Nmap'   ][0]
    cfg_logfile =data['LogFile'][0]            
    
    # CHECKING CONFIG - DATABASE ACCESS
    if cfg_mysql_cr ==None:
        exit(10)
    if cfg_mysql_cr['host'    ]==None or len(cfg_mysql_cr['host'    ])==0:
        exit(11)
    if cfg_mysql_cr['database']==None or len(cfg_mysql_cr['database'])==0:
        exit(12)
    if cfg_mysql_cr['user'    ]==None or len(cfg_mysql_cr['user'    ])==0:
        exit(13)
    if cfg_mysql_cr['password']==None or len(cfg_mysql_cr['password'])==0:
        exit(14)
    # CHECKING CONFIG - LOGFILES
    if cfg_logfile['number']==None or int(cfg_logfile['number'])==0:
        exit(30)
    if cfg_logfile['age'   ]==None or int(cfg_logfile['age'   ])==0:
        exit(31)

    # TIMESTAMP
    tst='{:%Y-%m-%d--%H-%M-%S}'.format(datetime.datetime.now())
    print('ipc4orgid: START TIME STAMP ',tst) 
    # UPDATE status
    json_inf={"tst_st":tst, "tst_sp":'', "status":'WEB JOB RUNNING'}
    with open(inf_file, 'w') as outfile:
        json.dump(json_inf, outfile)

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
        print ('ipc4orgid: scan ORG_ID '+org_id)
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
        print ('ipc4orgid: SCAN CMD ',cmd)
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
        print ('ipc4orgid: IMPORT ',cmd)
        sys.stdout.flush()
        sys.stderr.flush()
        os.system(cmd)
    
    # TIMESTAMP
    tnd='{:%Y-%m-%d--%H-%M-%S}'.format(datetime.datetime.now())
    print('ipc4orgid: STOP TIME STAMP ',tnd) 
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
