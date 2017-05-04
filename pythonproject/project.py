import argparse
import hashlib
import urllib
from datetime import datetime

def generate(ifileName):
    ifile = open(ifileName, 'r')
    ofile = open('database.rbt', 'w')

    found = 0

    start = datetime.now()

    for line in ifile:
        password = line.strip()     # removes whitespace
        md5 = hashlib.md5(password.encode()).hexdigest()        # create md5 hash for password
        sha1 = hashlib.sha1(password.encode()).hexdigest()      # create sha1 hash for password
        ofile.write(md5+':'+sha1+':'+password+'\n')     # md5 : sha1 : password
        found += 1

    ifile.close()
    ofile.close()

    end = datetime.now()

    total = end - start

    print 'Number of hashes created: ' + str(found)
    print 'Time to create the table: ' + str(total.microseconds) + ' microseconds'

def crack(hashtype, ifileName, ofileName):
    ifile = open(ifileName, 'r')
    ofile = open(ofileName, 'w')

    found = 0       # number of hashes found
    cracked = 0     # number of hashes cracked

    # database file
    try:
        db = open('database.rbt', 'r')
    except:
        print 'Unable to retrieve database file'
        quit()

    hash2pass = {}  # dictionary => key: hashcode, value: password

# filling up dictionary (from database)
# keys: hashes      values: passwords
    start = datetime.now()

    for line in db:     # look through rainbow table in database.rbt
        line = line.strip()
        splitstring = line.split(':')
        if (hashtype == 'md5'):     # md5 hash is at index 0
            hash2pass[splitstring[0]] = splitstring[2]      # add a new entry
        elif (hashtype == 'sha1'):      # sha1 hash is at index 1
            hash2pass[splitstring[1]] = splitstring[2]

    end = datetime.now()

    total = end - start

    for line in ifile:      # look through hashes
        hashcode = line.strip()     # remove whitespace
        if (hashcode in hash2pass):     # look up hashcode in dictionary
            password = hash2pass[hashcode]      # retrieve the password from dictionary
            ofile.write(hashcode+':'+password+'\n')      # write the cracked password to output file
            cracked += 1
        found += 1

    ifile.close()
    ofile.close()

    print 'Number of hashes found: ' + str(found)
    print 'Number of hashes cracked: ' + str(cracked)
    print 'Time to crack the hashes: ' + str(total.microseconds) + ' microseconds'
    print 'Type of hash used to crack: ' + hashtype


def validInput(args):
    if (args.ops != "generate" and args.ops != "crack"):
        print "Invalid operations flag"
        return False

    elif (args.ops == "crack" and args.t != "md5" and args.t != "sha1"):
        print "Invalid hash type"
        return False

    elif (args.ops == "crack" and args.o == None):
        print "No output file specified"
        return False

    elif (args.i == None):
        print "No input file specified"
        return False

    return True

def exists(ifileName):
    try:
        with open(ifileName): pass
    except IOError:
        print "Unable to retrieve input file"
        return False
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-ops')     # operations flag: 'generate' or 'crack'
    parser.add_argument('-t')       # type of hash: 'md5' or 'sha1'
    parser.add_argument('-i')       # input file
    parser.add_argument('-o')       # output file (can only be used for 'crack')
    args = parser.parse_args()

    if (validInput(args)):

        ifile = args.i

        try:        # try to download input file
            ifile = urllib.urlretrieve(ifile)[0]
        except:
            try:        # try to open a local input file
                with open(ifile): pass
            except IOError:
                print "Unable to retrieve input file"
                quit()

        if (args.ops == 'generate'):
            generate(ifile)
        elif (args.ops == 'crack'):
            crack(args.t, ifile, args.o)
