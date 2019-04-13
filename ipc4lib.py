#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' ipc4lib - IP collector tool functions
            * Tool functions of any kind.


    This program is part of the Scan2 Suite.
    https://github.com/dweKNOWLEDGEisFREE

    This program is licensed under the GNU General Public License v3.0

    Copyright 2019 by David Weyand, Ernst Schmid

'''


# DELETE OLD LOG FILES
#
# now   : current time.
# path  : Log file path.
# ext   : Extension of the log files.
# minLog: Minimum number of log files.
# maxAge: Maximum age of the log files.
def delOldLogFiles(now, path, ext, minLog, maxAge):
    
    import os, sys, datetime    
            
    # Retrieves File List
    def getFileList(path, ext):
        # Check incomming variable
        if path==None or ext==None:
            return []
        # Search directory
        dat=[]
        try:
            lst = os.listdir(path)
        except OSError:
            pass #ignore errors
        else:
            for name in lst:
                fn = os.path.join(path, name)
                nm=name.split('.')
                if not os.path.isdir(fn) and len(nm)>1 and nm[len(nm)-1].lower()==ext:
                    dat.append(nm[0])
        # return list of files
        return dat

    # Filename: 2018-04-21--05-00-02--5
    def getDateTimeFromName (name):
        # Check incomming variable
        if name==None or len(name)<22:
            return None
        # Separating elements
        try:
            tmp=name.split("-")
            age=datetime.datetime(int(tmp[0]),int(tmp[1]),int(tmp[2]),int(tmp[4]),int(tmp[5]),int(tmp[6]))
        except:
            print('getDateTimeFromName ERROR: ['+str(name)+']', file=sys.stdout)
            return None
        else:
            return age
    
    
    # Search HTML directory
    lst=getFileList(path, ext)
    # Check if more files than minimum number of files
    if len(lst)<minLog:
        return
    # Sorting list of files
    lst.sort(reverse=True)
    # Searching for old entries
    for idx in range(minLog, len(lst)):
        tmp=getDateTimeFromName(lst[idx])
        if tmp==None:
            continue
        if (now-tmp).days>maxAge:
            try:
                os.remove(os.path.join(path, lst[idx]+'.'+ext))
            except OSError as e:
                print ("delOldLogFiles ERROR: %s - %s." % (e.filename, e.strerror))
#           print ('DELETE '+str(os.path.join(path, lst[idx]+'.'+ext)))
#           print ('delete ['+lst[idx]+'] ['+str((now-tmp).days)+'] ['+str(now-tmp)+']')
#       else:
#           print ('keep   ['+lst[idx]+'] ['+str((now-tmp).days)+'] ['+str(now-tmp)+']')
    # List all files
#   for x in lst:
#       print(x)
    # All done
    return



''' DEBUG AND TESTING
'''
if __name__ == '__main__':
    print ('ipc4lib');
