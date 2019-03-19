#!/usr/bin/python3.5
# encoding: utf-8
''' ipc4jobj -- ip collector xml to database
    
    ipc4job is to insert data out of the xml file into the database.

    It defines classes_and_methods

    @author:     EJS
    @copyright:  2017 TBD. All rights reserved.
    @license:    TBD
    @contact:    TBD
    @deffield    updated: Updated
'''

import sys, os, argparse, mysql.connector, tempfile, xml.sax

__all__     = []
__version__ = 0.3
__date__    = '2017-10-26'
__updated__ = '2018-03-28'

DEBUG   = 0
TESTRUN = 0
PROFILE = 0


''' Extracting: IPv4, MAC, HOSTNAME
'''
class nMapHandler( xml.sax.ContentHandler ):
    def __init__(self, target):
        self.target=target
    def startElement(self, tag, attrs):
        self.dat_tag = tag
        if tag == "host":
            self.dat_IPv4 = ""
            self.dat_MAC  = ""
            self.dat_NAME = ""
        elif tag == "address":
            if ('addrtype', 'ipv4') in attrs.items():
                for item in attrs.items():
                    if item[0] == 'addr':
                        self.dat_IPv4 = item[1]
                        break
            if ('addrtype', 'mac') in attrs.items():
                for item in attrs.items():
                    if item[0] == 'addr':
                        self.dat_MAC = item[1]
                        break
        elif tag == "hostname":
            if ('type', 'PTR') in attrs.items():
                for item in attrs.items():
                    if item[0] == 'name':
                        self.dat_NAME = item[1]
                        break
    def endElement(self, tag):
    #   if tag == "host" and len(self.dat_MAC)>0:
        if tag == "host":
            if self.target!=None:
                self.target.send((self.dat_IPv4, self.dat_MAC,self.dat_NAME))
            else:
                print ("host: ",self.dat_IPv4," ",self.dat_MAC," ",self.dat_NAME)

def nMapCoroutine(func):
    def start(*args, **kwargs):
        cr=func(*args, **kwargs)
        next(cr)
        return cr
    return start


''' Database: Checking access
'''
def dbAccess (host, database, user, password):
    access_data = {'host': host, 'database': database, 'user': user, 'password': password}
    try:
        print('ipc4job: connect')
        cnx = mysql.connector.connect(**access_data)
        cursor = cnx.cursor()
        print('ipc4job: query')
        query = ("SELECT org_id, ipv4, mac, name, upd, ts_new, ts_upd FROM hosts")
        cursor.execute(query)
        for (org_id, ipv4, mac, name, upd, ts_new, ts_upd) in cursor:
            print("ORG_ID:{} IP:{} MAC:{} NAME:{} FLG:{} NEW:{} UPD:{}".
                  format(org_id, ipv4, mac, name, upd, ts_new, ts_upd))
        cursor.close()
    except mysql.connector.Error as err:
        print(err)
    else:
        print('ipc4job: close')
        cnx.close()


''' MAIN
'''
class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg
    def __str__(self):
        return self.msg
    def __unicode__(self):
        return self.msg

def main(argv=None): # IGNORE:C0111
    '''Command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s .. %s. USAGE''' % (program_shortdesc, str(__date__))

    try:
        # Setup argument parser
        parser = argparse.ArgumentParser(description=program_license)
        # Version
        parser.add_argument('-V', '--version', action='version', version=program_version_message)
        # iTop ORG_ID
        parser.add_argument('-i', '--org', dest="org",  help="ORG ID for the XML input file.")
        # XML Input file, generated form nmap.
        parser.add_argument('-x', '--xml', dest="file", help="XML input file from nmap.")
        # Database parameters
        parser.add_argument('-s', '--srv', dest="srv",  help="mySQL server name.")
        parser.add_argument('-d', '--dbn', dest="name", help="mySQL database name.")
        parser.add_argument('-u', '--usr', dest="user", help="user name for mySQL access.")
        parser.add_argument('-p', '--pwd', dest="pwd",  help="password for mySQL access.")
        # Process arguments
        args = parser.parse_args()

        # ORG ID preselection
        job_org=0;
        if args.org!=None:
            job_org=args.org
            
        # Job selection
        job_xml=False
        if args.file!=None:
            job_xml=True
        job_sql=False
        if args.srv!=None and args.name!=None and args.user!=None and args.pwd!=None:
            job_sql=True                        

        ''' Parse XML file but no database access
        '''
        if job_xml==True and job_sql==False: 
            print('ipc4job: xml start')
            parser = xml.sax.make_parser()
            parser.setFeature(xml.sax.handler.feature_external_ges, False)
            parser.setFeature(xml.sax.handler.feature_validation,False)
            parser.setContentHandler(nMapHandler(None))
            parser.parse(open(args.file,"r"))
            print('ipc4job: xml stop')
            return 0

        ''' Database access only
        '''
        if job_xml==False and job_sql==True:
            dbAccess(args.srv, args.name, args.user, args.pwd)
            return 0 

        ''' Insert records into database
        '''
        if job_xml==True and job_sql==True:

            def readTmpIpMacName(fp):
                tmpD=()
                for x in range(3):
                    tmpS=""
                    tmpB = fp.read(1)
                    while tmpB != b"" and tmpB!=b"\n":
                        tmpS+=tmpB.decode()
                        tmpB=fp.read(1)
                    if tmpB == b"":
                        break;
                    tmpD = tmpD + (tmpS,)
                return tmpD

            @nMapCoroutine
            def datStore():
                while True:
                    event = (yield)
                    for dat in event:
                        dat+='\n'
                        fp_tmp.write (dat.encode('utf-8'))

            ''' open TEMP file '''
            print('ipc4job: TMP open')
            fp_tmp = tempfile.TemporaryFile()
            ''' scanning XML file '''
            print('ipc4job: XML access')
            parser = xml.sax.make_parser()
            parser.setFeature(xml.sax.handler.feature_external_ges, False)
            parser.setFeature(xml.sax.handler.feature_validation,False)
            parser.setContentHandler(nMapHandler(datStore()))
            parser.parse(open(args.file,"r"))
            ''' reset TEMP file position '''
            fp_tmp.seek(0)
            ''' reading ... '''
            access_data = {'host': args.srv, 'database': args.name, 'user': args.user, 'password': args.pwd}
            try:
                print('ipc4job: SQL connect')
                cnx = mysql.connector.connect(**access_data)
                cursor = cnx.cursor()
                ''' read loop '''
                while True:
                    tmpD=readTmpIpMacName(fp_tmp)
                    if tmpD == ():
                        break;
                    ''' insert or update data '''
                    cmd=("""INSERT INTO hosts(org_id,ipv4,mac,name,upd,ts_upd) VALUES (%s,%s,%s,%s,%s,NULL) ON DUPLICATE KEY UPDATE upd=IF(org_id<>%s OR mac<>%s OR name<>%s,2,upd), org_id=%s, mac=%s, name=%s, ts_upd=NOW()""")
                    cursor.execute(cmd, (job_org, tmpD[0], tmpD[1], tmpD[2], 1,  job_org, tmpD[1], tmpD[2],  job_org, tmpD[1], tmpD[2]))
                #   print(cmd)
                #   print(cursor.statement)
                cursor.close()
                cnx.commit()
            except mysql.connector.Error as err:
                print(cursor.statement)
                print(err)
                cnx.rollback()
            else:
                print('ipc4job: SQL close')
                cnx.close()
            ''' close TEMP file '''
            fp_tmp.close()
            print('ipc4job: TMP close')
            return 0
        
        return 0
    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return 0
    except Exception as e:
        if DEBUG or TESTRUN:
            raise(e)
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")
        return 2


if __name__ == "__main__":
    if DEBUG:
        sys.argv.append("-h")
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = 'job.main_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())
    