#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' ipc4scan - Accesses nmap and xalan
             * ipc4scan starts nmap to scan the network.
             * The xml output file is converted by xalan into html.


    This program is part of the Scan2 Suite.
    https://github.com/dweKNOWLEDGEisFREE

    This program is licensed under the GNU General Public License v3.0

    Copyright 2019 by David Weyand, Ernst Schmid

'''


import sys, os, argparse, mysql.connector, ipaddress, tempfile

__all__     = []
__version__ = 0.3
__date__    = '2017-10-20'
__updated__ = '2018-03-28'

DEBUG   = 0
TESTRUN = 0
PROFILE = 0

# Configuration data
cfg_ip_file = 'tmp-ip-list-0.txt'


''' Database: Requesting IP LIST
'''
def dbAccessIP (host, database, user, password, org_id):
    access_data = {'host': host, 'database': database, 'user': user, 'password': password}
    # Result list
    res=[]
    try:
        print('ipc4scan: connect')
        cnx = mysql.connector.connect(**access_data)
        cursor = cnx.cursor()
        print('ipc4scan: query')
        query = ("SELECT DISTINCT firstip, lastip FROM jobs WHERE org_id=%s ORDER BY firstip")
        cursor.execute(query, [org_id])
    #   print('res:'+str(cursor))
        for (firstip, lastip) in cursor:
            res.append([firstip, lastip])
        #   print("ipc4scan: IP RANGE = "+firstip+" -> "+lastip)
        cursor.close()
    except mysql.connector.Error as err:
        print(cursor.statement)
        print(err)
    else:
        print('ipc4scan: close')
        cnx.close()
    return res


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

    program_name            = os.path.basename(sys.argv[0])
    program_version         = "v%s" % __version__
    program_build_date      = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc       = __import__('__main__').__doc__.split("\n")[1]
    program_license         = '''%s .. %s. USAGE''' % (program_shortdesc, str(__date__))

    try:
        # Setup argument parser
        parser = argparse.ArgumentParser(description=program_license)
        # Version 
        parser.add_argument('-V', '--version', action='version', version=program_version_message)
        # Database parameters
        parser.add_argument('-s', '--srv', dest="srv",  required=True, help="mySQL server name.")
        parser.add_argument('-d', '--dbn', dest="name", required=True, help="mySQL database name.")
        parser.add_argument('-u', '--usr', dest="user", required=True, help="mySQL user name.")
        parser.add_argument('-p', '--pwd', dest="pwd",  required=True, help="mySQL password.")
        # Additional parameters
        parser.add_argument("-on", "--nmap",  metavar="OPT",  dest="opt_nmap",  help="parameters for nmap. (SCAN->XML)")
        parser.add_argument("-ox", "--xalan", metavar="OPT",  dest="opt_xalan", help="parameters for xalan. (XML->HTML)")
        parser.add_argument("-fx", "--xml",   metavar="FILE", dest="file_xml",  help="xml file name.")
        parser.add_argument("-fh", "--htm",   metavar="FILE", dest="file_htm",  help="html file name.")
        # iTop ORG ID
        parser.add_argument('-id', '--org_id', dest="org_id", required=True, help="org_id to look for.")
        # List ORG Jobs / IP Jobs
        parser.add_argument('-lst', '--lstORG', action='store_true', help="print ORG list.")
        # Process arguments
        args = parser.parse_args()
        
        # Check database access parameters
        if args.srv==None or args.name==None or args.user==None or args.pwd==None:
            return 0

        ''' Print IP list
        '''
        if args.lstORG==True and args.org_id!=None:
            # open TEMP IP LIST file '''
            print('ipc4scan: List IPs')
            # Get IP ranges
            lst=dbAccessIP(args.srv, args.name, args.user, args.pwd, args.org_id)
            # Create IP addresses
            for dat in lst:
                print ('ipc4scan: list for '+str(dat))
                cnt=int(ipaddress.IPv4Address(dat[0])+1)
                while cnt<int(ipaddress.IPv4Address(dat[1])):
                    print ('ipc4scan: '+str(ipaddress.IPv4Address(cnt)))
                    cnt+=1
            # Exit
            return 0

        ''' Scan for the specified ORG_ID
        '''
        if args.org_id!=None:
            # open TEMP IP LIST file '''
            fn_ip=os.path.join(tempfile.gettempdir(), cfg_ip_file)
            print('ipc4scan: IP LIST open ['+fn_ip+']')
            fp_ip=open(str(fn_ip), "w+")
            # Get IP ranges
            lst=dbAccessIP(args.srv, args.name, args.user, args.pwd, args.org_id)
            # Generate liste of IP addresses.
            for dat in lst:
                print ('ipc4scan: list for '+str(dat))
                cnt=int(ipaddress.IPv4Address(dat[0])+1)
                while cnt<int(ipaddress.IPv4Address(dat[1])):
                    print (str(ipaddress.IPv4Address(cnt)))
                    fp_ip.write(str(ipaddress.IPv4Address(cnt))+'\n')
                    cnt+=1
            # close TEMP IP LIST file '''
            fp_ip.close()
            print('ipc4scan: TMP close')
            # Check nmap options
            if args.opt_nmap == None:
                args.opt_nmap   =(' -sn -PE -iL '+fn_ip+' ')
#               args.opt_nmap   =(' -iL '+fn_ip+' ')
            else:
                args.opt_nmap=(' -iL '+fn_ip+' '+args.opt_nmap+' ')
            # start nmap
            sys.stdout.flush()
            sys.stderr.flush()
            if args.file_xml!=None and len(args.file_xml)>0:
                os.system('nmap '+args.opt_nmap+' -sn -oX '+
                          args.file_xml.replace("%d", str(args.org_id)))
            else:
                os.system('nmap '+args.opt_nmap+' -sn')
            # start xalan
            if args.file_xml!=None and len(args.file_xml)>0:
                sys.stdout.flush()
                sys.stderr.flush()
                if args.file_htm!=None and len(args.file_htm)>0:
                    os.system('xalan -in '+args.file_xml.replace("%d", str(args.org_id))
                              +' -html -out '+args.file_htm.replace("%d", str(args.org_id)))
                else:
                    os.system('xalan -in '+args.file_xml.replace("%d", str(args.org_id))+' -html')
            # delete file
            os.remove(fn_ip)
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
        sys.argv.append("-v")
        sys.argv.append("-r")
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = 'main_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())
    