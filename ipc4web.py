#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' ipc4web - IP collector web interface
            * Responsible for all http related stuff.


    This program is part of the Scan2 Suite.
    https://github.com/dweKNOWLEDGEisFREE

    This program is licensed under the GNU General Public License v3.0

    Copyright 2019 by David Weyand, Ernst Schmid

'''


# Imports used by LOG FILE etc.
import os, sys, crontab, datetime
import json, requests
import ipc4lib

# Imports for Flask
from flask import Flask, render_template, request
from flask import redirect

# Imports and config data of CONFIG
from flask_wtf import Form
from wtforms   import HiddenField, SelectField, BooleanField, StringField, IntegerField, validators

# Imports used by DATABASE
import mysql.connector



# Database Structure
'''
CREATE DATABASE `ipc4iTopDB` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;
CREATE TABLE `hosts` (
  `ipv4` varchar(20) NOT NULL,
  `mac` varchar(30) DEFAULT '',
  `name` varchar(255) DEFAULT '',
  `upd` int(11) DEFAULT '0',
  `ts_new` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ts_upd` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `org_id` int(11) DEFAULT '0',
  PRIMARY KEY (`ipv4`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE `jobs` (
  `org_id` int(11) DEFAULT '0',
  `org_name` varchar(255) DEFAULT '',
  `firstip` varchar(20) NOT NULL,
  `lastip` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
'''



# Configuration data
cfg_file = 'config.json'
log_file = 'jobs.json'

# Path settings
path_XML  = './data/logfiles'
path_HTML = './static/data/logfiles'
path_iTop = './itop/conf/params.local.xml' 


# iTop ACCESS DATA
cfg_itop_cr = {
    'url' : 'http://iTop',
    'usr' : 'iTopUSR',
    'pwd' : 'iTopPWD'
}

# mySQL ACCESS DATA
cfg_mysql_cr = {
    'host'    : 'localhost',
    'database': 'IPCdatab',
    'user'    : 'IPCadmin',
    'password': 'IPCpassw'
}

# Crontab PARAMETERS
cfg_crontab = {
    'doQuery' : False,
    'doScan'  : False,
    'doUpdate': False,
    'doClean' : False, 
    'time'    : 0,
    'id'      : 'Scan2IP'
}

# Nmap PARAMETERS
cfg_nmap = {
    'parameter' : ''
}

# Log File PROCESSING
cfg_logfile = {
    'number' : 100,
    'age'    : 28
}


''' iTop XML LOAD CONFIG
'''
def config_iTop_load():
    # import element tree
    import xml.etree.ElementTree as ET 

    def readELEM(root, name):
        # Reading element data
        elems = root.findall(name)
        for elem in elems:
            return elem.text
        return None

    # info
    print('ipc4web: reading iTop parameters', file=sys.stdout)
    try:
        #import xml file
        tree = ET.parse(path_iTop)
        root = tree.getroot()
        # iTop url
        tmp=readELEM(root, "itop_url")
        if tmp!=None:
            cfg_itop_cr['url']=tmp
        # iTop usr
        tmp=readELEM(root, "itop_login")
        if tmp!=None:
            cfg_itop_cr['usr']=tmp
        # iTop usr
        tmp=readELEM(root, "itop_password")
        if tmp!=None:
            cfg_itop_cr['pwd']=tmp
        # mySQL host
        tmp=readELEM(root, "sql_host")
        if tmp!=None:
            cfg_mysql_cr['host']=tmp
        # mySQL database
        tmp=readELEM(root, "sql_database")
        if tmp!=None:
            cfg_mysql_cr['database']=tmp
        # mySQL user
        tmp=readELEM(root, "sql_login")
        if tmp!=None:
            cfg_mysql_cr['user']=tmp
        # mySQL password
        tmp=readELEM(root, "sql_password")
        if tmp!=None:
            cfg_mysql_cr['password']=tmp
    except:
        print('ERROR..: config_iTop_load iTop READ ACCESS FAILED', file=sys.stderr)
        return


''' iTop XML SAVE CONFIG
'''
def config_iTop_save():
    # import element tree
    import xml.etree.ElementTree as ET 

    def writeELEM(root, name, data):
        # Reading element data
        elems = root.findall(name)
        for elem in elems:
            elem.text=data

    # info
    print('ipc4web: saving iTop parameters', file=sys.stdout)
    try:
        #import xml file
        tree = ET.parse(path_iTop)
        root = tree.getroot()
        # iTop url
        writeELEM(root, "itop_url",      cfg_itop_cr ['url'     ])
        # iTop usr
        writeELEM(root, "itop_login",    cfg_itop_cr ['usr'     ])
        # iTop usr
        writeELEM(root, "itop_password", cfg_itop_cr ['pwd'     ])
        # mySQL host
        writeELEM(root, "sql_host",      cfg_mysql_cr['host'    ])
        # mySQL database
        writeELEM(root, "sql_database",  cfg_mysql_cr['database'])
        # mySQL user
        writeELEM(root, "sql_login",     cfg_mysql_cr['user'    ])
        # mySQL password
        writeELEM(root, "sql_password",  cfg_mysql_cr['password'])
        # write it back
        tree.write(path_iTop)   
    except:
        print('ERROR..: config_iTop_save iTop ACCESS FAILED', file=sys.stderr)
        return



''' CONFIG CHECK
'''
def config_check():
    # Use global
    global cfg_itop_cr, cfg_mysql_cr, cfg_crontab, cfg_nmap, cfg_logfile
    # Checking CRONTAB job flags
    # Query iTop for a updates list of IP ranges (jobs).
    if cfg_crontab['doQuery']==None:
        cfg_crontab['doQuery']=False
    # Scan IP ranges for changes.    
    if cfg_crontab['doScan']==None:
        cfg_crontab['doScan']=False
    # Update iTop database.
    if cfg_crontab['doUpdate']==None:
        cfg_crontab['doUpdate']=False
    # CleanUp log files.
    if cfg_crontab['doClean']==None:
        cfg_crontab['doClean']=False
    # Checking CRONTAB TIME parameters
    if cfg_crontab['time']==None or int(cfg_crontab['time'])>=24*60:
        cfg_crontab['doQuery' ]=False
        cfg_crontab['doScan'  ]=False
        cfg_crontab['doUpdate']=False
        cfg_crontab['doClean' ]=False
        cfg_crontab['time'    ]=0
    # Checking LOGFILE parameters
    if cfg_logfile['number']==None or int(cfg_logfile['number'])<10:
        cfg_logfile['number']=10
    if cfg_logfile['age']==None or int(cfg_logfile['age'])<7:
        cfg_logfile['age']=7

''' CONFIG LOAD
'''
def config_load():
    # loading
    try:
        with open(cfg_file) as json_file:
            # Use global
            global cfg_itop_cr, cfg_mysql_cr, cfg_crontab, cfg_nmap, cfg_logfile
            # load  
            data = json.load(json_file)
            # update
            cfg_itop_cr =data['iTop'   ][0]
            cfg_mysql_cr=data['mySQL'  ][0]
            cfg_crontab =data['Crontab'][0]
            cfg_nmap    =data['Nmap'   ][0]
            cfg_logfile =data['LogFile'][0]
            # info
            print('ipc4web: config file loaded', file=sys.stdout)
    except:
        print('ipc4web: no JSON read access', file=sys.stderr)
    # update with iTop parameters
    config_iTop_load()
    # checking
    config_check()
        

''' CONFIG SAVE
'''
def config_save():
    # checking
    config_check()
    # writing
    try:
        # Use global
        global cfg_itop_cr, cfg_mysql_cr, cfg_crontab, cfg_nmap, cfg_logfile
        # new config file
        data = {}
        data['iTop'   ]=[]
        data['iTop'   ].append(cfg_itop_cr)
        data['mySQL'  ]=[]
        data['mySQL'  ].append(cfg_mysql_cr)
        data['Crontab']=[]
        data['Crontab'].append(cfg_crontab)
        data['Nmap'   ]=[]
        data['Nmap'   ].append(cfg_nmap)
        data['LogFile']=[]
        data['LogFile'].append(cfg_logfile)
        # save
        with open(cfg_file, 'w') as outfile:
            json.dump(data, outfile)
        # info
        print('ipc4web: new config file created', file=sys.stderr)
    except:
        print('ipc4web: no JSON write access', file=sys.stderr)    
    # Update iTop configuration
    config_iTop_save()        
        
        

''' CRON CHECK
'''
def cron_active():
    # Use global
    global cfg_crontab
    # Check for active entries
    try:
        jobs=crontab.CronTab(user='root')
        for job in jobs:
            if job.comment == cfg_crontab['id']:
                return 'RUNNING'
        return 'OFFLINE'
    except:
        return 'UNKNOWN'

def cron_list():
    # Use global
    global cfg_crontab
    # List crontab entries
    print('ipc4web: cron jobs list', file=sys.stdout)
    try:
        jobs=crontab.CronTab(user='root')
        for job in jobs:
            print('ipc4web: job ['+job.__str__()+']', file=sys.stdout)
    except:
        print('ipc4web: no access to crontab', file=sys.stderr)
        
def cron_update():
    # Use global
    global cfg_crontab
    # Access crontab
    print('ipc4web: cron job update', file=sys.stdout)
    try:
        # request access
        jobs=crontab.CronTab(user='root')
        # Delete cron jobs
        jobs.remove_all(comment=cfg_crontab['id'])
        # Saveing list of jobs
        jobs.write()
        # Update cron jobs
        if not bool(cfg_crontab['doQuery' ]) and not bool(cfg_crontab['doScan' ]) and \
           not bool(cfg_crontab['doUpdate']) and not bool(cfg_crontab['doClean']):
            return
        # Timecheck
        if int(cfg_crontab['time'])<0:
            return
        # Create Cron Job
        # Get path
        dirname, filename = os.path.split(os.path.abspath(sys.argv[0]))
        # Create job
        job=jobs.new(command=dirname+'/ipc4cron.py', comment=cfg_crontab['id'])
        # Every day at ...
        time = int(cfg_crontab['time']) % (24*60)
        job.minute.on(time %  60)
        job.hour.on  (time // 60)
        jobs.write()
        print('ipc4web: job ['+job.__str__()+'] created.', file=sys.stdout)
        return
    except:
        return


''' DATABASE CLEANUP
'''
def dbCleanUp (host, database, user, password):
    access_data = {'host': host, 'database': database, 'user': user, 'password': password}
    # Result list
    try:
        print('ipc4web: connect')
        cnx = mysql.connector.connect(**access_data)
        cursor = cnx.cursor()
        print('ipc4web: delete')
        sqlcmd = ("DELETE FROM hosts WHERE (TO_SECONDS(now())-TO_SECONDS(ts_new))>86400")
        cursor.execute(sqlcmd)
        cursor.close()
        cnx.commit()
    except mysql.connector.Error as err:
        print(cursor.statement, file=sys.stderr)
        print(err, file=sys.stderr)
    else:
        print('ipc4web: close')
        cnx.close()
    return



# Booting up ...
print('ipc4web: Scan2IP ...',     file=sys.stdout)
print('ipc4web: test err output', file=sys.stderr)
print('ipc4web: test std output', file=sys.stdout)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['WTF_CSRF_ENABLED'] = False



''' FAVICON.ICO
'''
@app.route('/favicon.ico')
def url_favicon():
    print('url_favicon', file=sys.stderr)
    return app.send_static_file('favicon.ico')


''' REDIRECT from /
'''
@app.route('/')
def url_root():
    print('url_root', file=sys.stderr)
    return redirect("static/", code=302)

@app.route('/static/site/page/')
def url_page():
    print('url_page', file=sys.stderr)
    return app.send_static_file('site/page/index.html')



''' OVERVIEW
'''
@app.route('/static/')
def url_overview():
    print('url_overview', file=sys.stderr)
    return render_template("index.html")
#   return app.send_static_file('index.html')



''' STATUS
'''
@app.route('/static/site/status/')
def url_status():
    try:
        with open(log_file) as json_file:
            data=json.load(json_file)
            cur=data['cur'][0]
            lst=data['lst'][0]
            print (cur, lst)
    except:
        cur=""
        lst=""
    print (cur, lst)

    return render_template("site/status/index.html", cur=cur, lst=lst, cron=cron_active())
#   return app.send_static_file('site/status/index.html')



''' ACCESS DATA
'''
@app.route('/static/site/tools/', methods=["GET", "POST"])
def url_tools():

    # use global config variables
    global cfg_itop_cr, cfg_mysql_cr, cfg_crontab, cfg_nmap, cfg_logfile
        
    # Liste für IP-SCAN vorbereiten
    dborg  = []
    orgsel = ''
    # Datenbank abfragen
    try:
        # Connect
        print('ipc4web: connect', file=sys.stdout)
        cnx = mysql.connector.connect(**cfg_mysql_cr)
        cursor = cnx.cursor()
        # Query ORG_ID ORG_NAME
        query = ("SELECT DISTINCT org_id, org_name FROM jobs ORDER BY org_name, org_id")
        cursor.execute(query)
        # Output for ORG_ID ORG_NAME
        for (org_id, org_name) in cursor:
            dborg.append([org_id, org_name])
    except mysql.connector.Error as err:
        print(err, file=sys.stderr)
    else:
        # Close
        print('ipc4web: close', file=sys.stdout)
        cnx.close()

    class ToolForm(Form):
        # dummy parameters
        cfgToolQuery  = HiddenField ('Query')
        cfgToolScan   = HiddenField ('Scan')
        cfgToolUpdate = HiddenField ('Update')
        cfgToolClean  = HiddenField ('Clean')
        cfgOrgLst     = SelectField (choices=dborg, default=orgsel)

    # Request data
    toolForm = ToolForm(csrf_enabled=False)

    # Check for QUERY Button
    if request.method == 'POST' and not request.form.get('query') is None and toolForm.validate:
        # Info
        print('ipc4web: tool->query', file=sys.stdout)
        
        # REST
        try:
            # REST REQUEST CREATE
            json_data = {
    #           'operation': 'list_operations'
                'operation': 'core/get',
                'class'    : 'IPv4Range',
                'key'      : "SELECT IPv4Range"
            }
            encoded_data = json.dumps(json_data)
            # REST REQUEST TRANSMITT
            print (cfg_itop_cr.get('url'))
            print (cfg_itop_cr.get('usr'))
            print (cfg_itop_cr.get('pwd'))

            res = requests.post(cfg_itop_cr.get('url')+'/webservices/rest.php?version=1.0', verify=False,
                                data={'auth_user': cfg_itop_cr.get('usr'), 
                                      'auth_pwd': cfg_itop_cr.get('pwd'),
                                      'json_data': encoded_data})
        except:
            print('ipc4web: tool->query ... failed', file=sys.stderr)
            print(res, file=sys.stderr)
            return render_template("site/tools/index.html", form=toolForm, org=dborg)

        print(res)
        # DATABASE TRANSFER
        result = json.loads(res.text);
        print(result);
        if result['code'] == 0:
            # Transfer data into SQL-DB
            try:
                print('ipc4web: SQL connect')
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
                print('ipc4web: SQL close')
                cnx.close()

    # Check for CLEANUP Button
    if request.method == 'POST' and not request.form.get('clean') is None and toolForm.validate:
        # Info
        print('ipc4web: tool->clean', file=sys.stdout)
        # CleanUp Database
        dbCleanUp(cfg_mysql_cr['host'], cfg_mysql_cr['database'], cfg_mysql_cr['user'], cfg_mysql_cr['password'])

    # Check for SCAN Button
    if request.method == 'POST' and not request.form.get('scan') is None and toolForm.validate:
        # Info
        print('ipc4web: tool->scan  for org_id ', str(toolForm.cfgOrgLst.data), file=sys.stdout)
        orgsel=toolForm.cfgOrgLst.data
        # BUILD SCAN COMMAND
        if len(str(toolForm.cfgOrgLst.data))>0:
               cmd=('./ipc4orgid.py '+str(toolForm.cfgOrgLst.data)+'&')
               print ('ipc4web: SCAN CMD ',cmd)
               sys.stdout.flush()
               sys.stderr.flush()
               os.system(cmd)
               print ('ipc4web: SCAN CMD running',cmd)

    # Check for UPDATE Button
    if request.method == 'POST' and not request.form.get('update') is None and toolForm.validate:
        # Info
        print('ipc4web: tool->update', file=sys.stdout)
        # BUILD UPDATE COMMAND
        cmd=('cd itop;php exec.php&')
        print ('ipc4web: UPDATE CMD ',cmd)
        sys.stdout.flush()
        sys.stderr.flush()
        os.system(cmd)
        print ('ipc4web: SCAN UPDATE running',cmd)

    # Check for QUERY Button
    if request.method == 'POST' and not request.form.get('cleanLog') is None and toolForm.validate:
        # Info
        print('ipc4web: tool->clean', file=sys.stdout)
        # Get current time and date.
        now=datetime.datetime.today()
        # CleanUp of HTML Log File Directory
        ipc4lib.delOldLogFiles(now, path_HTML, 'html', cfg_logfile['number'], cfg_logfile['age'])
        # CleanUp of XML Log File Directory
        ipc4lib.delOldLogFiles(now, path_XML,  'xml', cfg_logfile['number'], cfg_logfile['age'])

    return render_template("site/tools/index.html", form=toolForm)
#   return app.send_static_file('site/tools/index.html')



''' CONFIGURATION ACCESS IP JOBS DATABASE CHRON NMAP
'''    
@app.route('/static/site/config/', methods=["GET", "POST"])
def url_config():
    
    class ConfigForm(Form):
        # iTop access parameters
        cfgItopUrl  = StringField (u'iTop URL:', 
                                  [validators.Length(min=0, max=50)], default=cfg_itop_cr['url'])
        cfgItopUser = StringField (u'iTop User name:', 
                                  [validators.Length(min=0, max=50)], default=cfg_itop_cr['usr'])
        cfgItopPwd  = StringField (u'iTop Password:', 
                                  [validators.Length(min=0, max=50)], default=cfg_itop_cr['pwd'])
        # Database access parameters
        cfgMysqlHost = StringField (u'Hostname:', 
                                  [validators.Length(min=0, max=50)], default=cfg_mysql_cr['host'])
        cfgMysqlDb   = StringField (u'Database name:', 
                                  [validators.Length(min=0, max=50)], default=cfg_mysql_cr['database'])
        cfgMysqlUser = StringField (u'Username:', 
                                  [validators.Length(min=0, max=50)], default=cfg_mysql_cr['user'])
        cfgMysqlPwd  = StringField (u'Password:', 
                                  [validators.Length(min=0, max=50)], default=cfg_mysql_cr['password'])
        # Crontab Parameters
        tmHH=[]
        for i in range(0, 24, 1):
            tmHH+=[(str(i), str(i))]
        cfgScanTimeH = SelectField (choices=tmHH, default=str(int(cfg_crontab['time'])//60))
        tmMM=[]
        for i in range(0, 60, 5):
            tmMM+=[(str(i), str(i))]
        cfgScanTimeM = SelectField (choices=tmMM, default=str(((int(cfg_crontab['time'])//5)*5)%60))
        cfgDoQuery  = BooleanField(default=bool(cfg_crontab['doQuery']))
        cfgDoScan   = BooleanField(default=bool(cfg_crontab['doScan']))
        cfgDoUpdate = BooleanField(default=bool(cfg_crontab['doUpdate']))
        cfgDoClean  = BooleanField(default=bool(cfg_crontab['doClean']))
        # Other configuration parameters
        cfgNmapParm  = StringField ('Nmap command line options:', 
                                    [validators.Length(min=0, max=200)], default=cfg_nmap['parameter'])
        cfgLogNumber = IntegerField('Total number of log files:', 
                                    [validators.Length(min=0, max=4)], default=cfg_logfile['number'])
        cfgLogAge    = IntegerField('Maximum age of log files (days):', 
                                    [validators.Length(min=0, max=3)], default=cfg_logfile['age'])
    
    # use global config variables
    global cfg_itop_cr, cfg_mysql_cr, cfg_crontab, cfg_nmap, cfg_logfile
    
    cfgForm = ConfigForm(csrf_enabled=False)
    
    if request.method == 'POST' and cfgForm.validate:
        # Updating iTop configuration
        cfg_itop_cr['url']=cfgForm.cfgItopUrl.data
        cfg_itop_cr['usr']=cfgForm.cfgItopUser.data
        cfg_itop_cr['pwd']=cfgForm.cfgItopPwd.data
        # Updating database configuration
        cfg_mysql_cr['host'    ]=cfgForm.cfgMysqlHost.data
        cfg_mysql_cr['database']=cfgForm.cfgMysqlDb.data
        cfg_mysql_cr['user'    ]=cfgForm.cfgMysqlUser.data
        cfg_mysql_cr['password']=cfgForm.cfgMysqlPwd.data
        # Updating crontab configuration parameters
        cfg_crontab['doQuery' ]=cfgForm.cfgDoQuery.data
        cfg_crontab['doScan'  ]=cfgForm.cfgDoScan.data
        cfg_crontab['doUpdate']=cfgForm.cfgDoUpdate.data
        cfg_crontab['doClean' ]=cfgForm.cfgDoClean.data
        cfg_crontab['time'    ]=int(cfgForm.cfgScanTimeH.data)*60+int(cfgForm.cfgScanTimeM.data)
        # Updating other configuration parameters
        cfg_nmap['parameter']=cfgForm.cfgNmapParm.data
        cfg_logfile['number']=cfgForm.cfgLogNumber.data
        cfg_logfile['age'   ]=cfgForm.cfgLogAge.data
        # Config Data Update
        config_save()
        cron_update()
        
    return render_template("site/config/index.html", form=cfgForm)
#   return app.send_static_file('site/config/index.html')



''' JOBS
'''
@app.route('/static/site/jobs/')
def url_jobs():
    # Liste vorbereiten
    dbdata = [['#', 'ORG ID', 'ORG NAME', 'FIRST IP', 'LAST IP']]
    # Datenbank abfragen
    try:
        # Connect
        print('ipc4web: connect', file=sys.stdout)
        cnx = mysql.connector.connect(**cfg_mysql_cr)
        cursor = cnx.cursor()
        # Query
        print('ipc4web: query', file=sys.stdout)
        query = ("SELECT org_id, org_name, firstip, lastip FROM jobs ORDER BY org_name, org_id, firstip, lastip")
        cursor.execute(query)
        # Output
        cnt=0
        for (org_id, org_name, firstip, lastip) in cursor:
            cnt = cnt + 1
            dbdata.append([cnt, org_id, org_name, firstip, lastip])
        #   print("IP:{} HOSTNAME:{}".format(ipv4, name), file=sys.stdout)
    except mysql.connector.Error as err:
        print(err, file=sys.stderr)
    else:
        # Close
        print('ipc4web: close', file=sys.stdout)
        cnx.close()
    # Output
#   print(dbdata, file=sys.stdout)
    return render_template("site/jobs/index.html", results=dbdata)
#   return app.send_static_file('site/jobs/index.html')



''' DATABASE
'''
@app.route('/static/site/database/')
def url_database():
    # Liste vorbereiten
    dbdata = [['#', 'ORG ID', 'IP', 'MAC', 'HOSTNAME', 'UPDATE']]
    # Datenbank abfragen
    try:
        # Connect
        print('ipc4web: connect', file=sys.stdout)
        cnx = mysql.connector.connect(**cfg_mysql_cr)
        cursor = cnx.cursor()
        # Query
        print('ipc4web: query', file=sys.stdout)
        query = ("SELECT org_id, ipv4, mac, name, upd FROM hosts")
        cursor.execute(query)
        # Output
        cnt=0
        for (org_id, ipv4, mac, name, ts_new) in cursor:
            cnt = cnt + 1
            dbdata.append([cnt, org_id, ipv4, mac, name, ts_new])
        #   print("IP:{} HOSTNAME:{}".format(ipv4, name), file=sys.stdout)
    except mysql.connector.Error as err:
        print(err, file=sys.stderr)
    else:
        # Close
        print('ipc4web: close', file=sys.stdout)
        cnx.close()
    # Output
#   print(dbdata, file=sys.stdout)
    return render_template("site/database/index.html", results=dbdata)
#   return app.send_static_file('site/database/index.html')



''' LOG FILES
'''
def make_entries(path):
    result=[]
    try: lst = os.listdir(path)
    except OSError:
        pass #ignore errors
    else:
        for name in lst:
            fn = os.path.join(path, name)
            nm=name.split('.')
#           print(nm, file=sys.stdout)
            if not os.path.isdir(fn) and len(nm) > 1 and nm[len(nm)-1].lower() == 'html':
            #   print(nm, file=sys.stdout)
                result.append(nm[0])
    result.sort(reverse=True)
    return result

@app.route('/static/site/logfiles/')
def url_logfiles():
#   print('-->', file=sys.stdout)
    logs=make_entries(path_HTML)
#   print(logs, file=sys.stderr)
#   print('<--', file=sys.stdout)
    return render_template("site/logfiles/index.html", ref='static/data/logfiles/', ext='.html', list=logs)
#   return app.send_static_file('site/logfiles/index.html')



''' RUN SERVER
'''
if __name__ == '__main__':
    # SHOW PATH
    print('ipc4web: Path - ',sys.argv[0])
    dirname, filename = os.path.split(os.path.abspath(sys.argv[0]))
    print ("ipc4web: running from - ", dirname)
    os.chdir(dirname)
    # SHOW USER ID
    print('ipc4web: Real UserID - %d' % os.getuid())
    print('ipc4web: Effective UserID - %d' % os.geteuid())
    # get the config data.
    config_load()
    # list cron jobs
    cron_list()
#   cron_update()    
    # starting web server
    app.run(host= '0.0.0.0', port=5000)
