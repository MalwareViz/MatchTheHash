#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib, sys, os, fnmatch, argparse, time

'''
MIT License.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

__description__ = 'Match the hash values on a computer to hash values in a file.'
__author__ = 'Craig Field'
__version__ = '0.1.0'
__date__ = '2014/10/07'

#Open CSV or text file with sample hashes in comma delimited format using md5 or sha1:
#name1,size,MD5
#name2,size,SHA1
#
#Get the highest file size of the samples.
#Loop through file system matching file size.
#On file sizes that match, check md5 or sha1 to see if it matches sample.
#print examples to screen.
#print results to file.
#
#ToDo:
#    Be able to send results to a server.


knownBadfiles = []

#These are function to get the hash values.
def md5sum(filename):
    try:
        blocksize = 65536
        hash = hashlib.md5()
        with open(filename, 'rb') as afile:
            buffer = afile.read(blocksize)
            while len(buffer) > 0:
                hash.update(buffer)
                buffer = afile.read(blocksize)
        return (hash.hexdigest())
    except Exception,e:
        print e

def sha1(filename):
    try:
        blocksize = 65536
        hash = hashlib.sha1()
        with open(filename, 'rb') as afile:
            buffer = afile.read(blocksize)
            while len(buffer) > 0:
                hash.update(buffer)
                buffer = afile.read(blocksize)
        return (hash.hexdigest())
    except Exception,e:
        print e


#Get the highest file size of the known bad samples.
#This will be used so file larger than this will not be searched.


def parseFiles(path, filter):
     for root, dirs, files in os.walk(path):
          for file in fnmatch.filter(files, filter):
               yield os.path.join(root, file)


#Loop through File System matching file size.
#On file sizes that match, check md5 or sha1 to see if it matches sample.
#print examples to screen.
#print results to file.

def findMaxSize(list):
    list2 = []
    try:
        for item in list:
            item = item.split(',')
            if item[1] != 0:
                list2.append(int(item[1])) #Change string into number with int().
        return max(list2) #Return max size of list.
    except Exception,e:
        print e


def getResultsFromFile(FilePath, knownBadfiles, infile, outfile):
    print "\nSearching hashes using: \n" + infile
    print "Starting search at: \n" + FilePath
    for entry in parseFiles(FilePath,'*'):
        if entry != None:
            try:
                entrySize = str(os.stat(entry).st_size) #'1430'
                maxSize = findMaxSize(knownBadfiles) #Error: "list index out of range" when spaces in input file.
                for line in knownBadfiles:
                    line = line.replace('\r','').replace('\n','')
                    line = str(line).split(',')
                    if int(entrySize) != None:
                        if int(entrySize) <= int(maxSize): #Anything less than max.
                            if entrySize == line[1]: #If filesize is equal to size of bad file sample.
                                if len(str(line[2])) == 32: #if the length is md5 hash.
                                        md5hash = md5sum(entry)
                                        if md5hash == str(line[2]):
                                            print '####################'
                                            print '#  Found Match!!!  #'
                                            print '####################'
                                            print '# '
                                            print '#  ' + 'Name:\t' + line[0]
                                            print '#  ' + 'Size:\t' + line[1]
                                            print '#  ' + 'MD5: \t' + line[2]
                                            print '#  ' + 'Path:\t' + entry
                                            print '#  '
                                            print '####################'
                                            print ''
                                            results = line[0] +','+ line[1] +','+ line[2] +','+ entry + '\n'
                                            #print results
                                            WriteToFile(outfile, results)
                                            continue

                                elif len(str(line[2])) == 40: #if the length is sha1 hash.
                                        sha1hash = sha1(entry)
                                        if sha1hash == str(line[2]):
                                            print '####################'
                                            print '#  Found Match!!!  #'
                                            print '####################'
                                            print '# '
                                            print '#  ' + 'Name:\t' + line[0]
                                            print '#  ' + 'Size:\t' + line[1]
                                            print '#  ' + 'SHA1:\t' + line[2]
                                            print '#  ' + 'Path:\t' + entry
                                            print '#  '
                                            print '####################'
                                            print ''
                                            results = line[0] +','+ line[1] +','+ line[2] +','+ entry + '\n'
                                            print results
                                            WriteToFile(outfile, results)
                                            continue
                                else:
                                    pass

            except Exception, e:
                #print e
                pass
                print 'Continuing...'

def getResultsOneEntry(FilePath, FileName, FileSize, HashValue, outfile):
    print "\nStart Matching at " + FilePath + " for: \n" + '  ' + FileName, FileSize, HashValue
    for entry in parseFiles(FilePath,'*'):
        try:
            entrySize = str(os.stat(entry).st_size) #'1430'
            if entrySize == FileSize: #If filesize is equal to size of bad file sample.
                if len(str(HashValue)) == 32: #if the length is md5 hash.
                    md5hash = md5sum(entry)
                    if md5hash == HashValue:
                        print '####################'
                        print '#  Found Match!!!  #'
                        print '####################'
                        print '# '
                        print '#  ' + 'Name:\t' + FileName
                        print '#  ' + 'Size:\t' + FileSize
                        print '#  ' + 'MD5:\t' + HashValue
                        print '#  ' + 'Path:\t' + entry
                        print '# '
                        print '####################'
                        print ''
                        results = FileName +','+ FileSize +','+ HashValue +','+ entry + '\n'
                        #print results
                        WriteToFile(outfile, results)
                        continue
                elif len(str(HashValue)) == 40: #if the length is sha1 hash.
                    sha1hash = sha1(entry)
                    if sha1hash == HashValue:
                        print '####################'
                        print '#  Found Match!!!  #'
                        print '####################'
                        print '# '
                        print '#  ' + 'Name:\t' + FileName
                        print '#  ' + 'Size:\t' + FileSize
                        print '#  ' + 'SHA1:\t' + HashValue
                        print '#  ' + 'Path:\t' + entry
                        print '# '
                        print '####################'
                        print ''
                        results = FileName +','+ FileSize +','+ HashValue +','+ entry + '\n'
                        #print results
                        WriteToFile(outfile, results)
                        continue
                else:
                    continue
        except Exception, e:
            #print e
            print 'Continue Matching...'
            print ''
            pass

#Search for a hash without having a file size. Slower than including file size.
def HashOnlySearch(FilePath, FileName, HashValue, outfile):
    print "\nStart Matching at " + FilePath + " for: \n" + '  ' + FileName, HashValue
    for entry in parseFiles(FilePath,'*'):
        try:
            entrySize = str(os.stat(entry).st_size) #'1430'
            if len(str(HashValue)) == 32: #if the length is md5 hash.
                md5hash = md5sum(entry)
                if md5hash == HashValue:
                    print '####################'
                    print '#  Found Match!!!  #'
                    print '####################'
                    print '# '
                    print '#  ' + 'Name:\t' + FileName
                    print '#  ' + 'Size:\t' + entrySize
                    print '#  ' + 'MD5:\t' + HashValue
                    print '#  ' + 'Path:\t' + entry
                    print '# '
                    print '####################'
                    print ''
                    results = FileName +','+ entrySize +','+ HashValue +','+ entry + '\n'
                    #print results
                    WriteToFile(outfile, results)
                    continue
            elif len(str(HashValue)) == 40: #if the length is sha1 hash.
                sha1hash = sha1(entry)
                if sha1hash == HashValue:
                    print '####################'
                    print '#  Found Match!!!  #'
                    print '####################'
                    print '# '
                    print '#  ' + 'Name:\t' + FileName
                    print '#  ' + 'Size:\t' + entrySize
                    print '#  ' + 'SHA1:\t' + HashValue
                    print '#  ' + 'Path:\t' + entry
                    print '# '
                    print '####################'
                    print ''
                    results = FileName +','+ entrySize +','+ HashValue +','+ entry + '\n'
                    #print results
                    WriteToFile(outfile, results)
                    continue
            else:
                continue

        except Exception, e:
            #print e
            print 'Continue Matching...'
            print ''
            pass

def parseFilesWholeHardDrive(path, filter):
     for root, dirs, files in os.walk(path):
          for file in fnmatch.filter(files, filter):
               yield file, os.path.join(root, file)

def getHashValueForWholeHardDrive(FilePath, hashmode, outfile):
    print "\nCreating Hash values starting at " + FilePath
    print "Results written to " + outfile
    for entry in parseFilesWholeHardDrive(FilePath,'*'):
        try:
            entrySize = str(os.stat(entry[1]).st_size) #'1430'
            if hashmode == 'md5_values':
                md5hash = md5sum(entry[1])
                NameEntry = entry[0]
                NameEntry = NameEntry.replace(',', '_')
                print '  ' + 'Name:\t' + NameEntry
                print '  ' + 'Size:\t' + entrySize
                print '  ' + 'MD5: \t' + md5hash
                print '  ' + 'Path:\t' + entry[1]
                print ''
                results = entry[0] +','+ entrySize +','+ md5hash +','+ entry[1] + '\n'
                #print results
                WriteToFile(outfile, results)
                continue
            elif hashmode == 'sha1_values':
                sha1hash = sha1(entry[1])
                NameEntry = entry[0]
                NameEntry = NameEntry.replace(',', '_')
                print '  ' + 'Name:\t' + NameEntry
                print '  ' + 'Size:\t' + entrySize
                print '  ' + 'SHA1:\t' + sha1hash
                print '  ' + 'Path:\t' + entry[1]
                print ''
                results = entry[0] +','+ entrySize +','+ sha1hash +','+ entry[1] + '\n'
                #print results
                WriteToFile(outfile, results)
                continue
            else:
                continue

        except Exception, e:
            #print e
            print 'Continue Matching...'
            print ''
            pass



def putResultsIntoFile(FolderPath, outfile):
    print "Creating Hash for files in folder: " + FolderPath
    list_files = []
    try:
        for root, dirs, files in os.walk(FolderPath):
            list_files.extend(files)
            break
        for name in list_files:
            filepath = FolderPath + os.sep + name
            entrySize = str(os.stat(filepath).st_size) #'1430'
            md5hash = md5sum(filepath)
            results = name +','+ entrySize +','+ md5hash + '\n'
            print results
            WriteToFile(outfile, results)
    except Exception, e:
        print e
        #pass


def WriteToFile(outfile, results):
    with open(outfile, 'a+') as f2:
        #f2.write(','.join(map(str,line))+'\n')
        #f2.write(','.join(map(str,getResults(FilePath)))+'\n')
        print 'Results written to: \n  ' + outfile + '\n  Continue...\n'
        f2.write(results)

#############################################
#Arguments parser
#########
usage = "\nMatchTheHash goes much faster if file size is included.\n\
  File sizes are matched first and then hash values. \n\
  \nExamples:\n\
  -size 179712 -md5 d378bffb70923139d6a4f546864aa61c \n\
  -hf folder_path -o samples.csv (Hash folder that contains malware samples.) \n\
   -i samples.csv -o results.csv (Sample data is input to search for matches.)\n\
  \n"


parser = argparse.ArgumentParser(description='Matches The Hash values to files on a machine.'
)
parser.add_argument('-name', action="store", dest="filename", help="Name of single file to search")
parser.add_argument('-size', action="store", dest="filesize", help="Size of file to search. Faster than hash only search.")
parser.add_argument('-md5', action="store", dest="md5hash", help="MD5 hash value to search.")
parser.add_argument('-sha1', action="store", dest="sha1hash", help="SHA1 hash value to search.")
parser.add_argument('-hf', action="store", dest="hash_folder", help="Hash contents of a folder.")
parser.add_argument('-hhd', action="store_true", dest="hash_harddrive", help="Hash contents of an entire hard drive: MD5.")
parser.add_argument('-hhdsha1', action="store_true", dest="hash_harddrivesha1", help="Hash contents of an entire hard drive: SHA1.")
parser.add_argument('-p', action="store", dest="path", help="Path to start in, else search whole disk.")

parser.add_argument('-i', action="store", dest="infile", help="CSV or text file in this format 'malwarename1.exe,size,MD5' or SHA1 hash value.'")
parser.add_argument('-o', action="store", dest="outfile", help="Output file.") # dest = name of variable
#parser.add_argument('-c', action="store", dest="Client")
#parser.add_argument('-s', action="store", dest="Server")

results = parser.parse_args()

filename = results.filename
filesize = results.filesize
md5hash  = results.md5hash
sha1hash = results.sha1hash
hash_folder = results.hash_folder
hash_harddrive = results.hash_harddrive
hash_harddrivesha1 = results.hash_harddrivesha1
filepath = results.path

infile = results.infile
cwdOutFile = os.getcwd() + os.sep + 'Match_The_Hash.csv'
outfile = results.outfile or cwdOutFile
#Client = results.Client
#Server = results.Server
#
#############################################

def main():
    SystemDrive = os.getenv('SystemDrive') #Example 'C:'
    if SystemDrive != None:
        SystemDrive = SystemDrive + os.sep #For Windows
    else:
        SystemDrive = os.sep
    filePath    = filepath or SystemDrive

    if len(sys.argv) == 1:
        parser.print_help()
        print usage
        sys.exit(0)

    if infile:
        try:
            with open(infile,"rb") as f:
                for line in f.readlines():
                    if line != None:
                        if line != '\r\n':
                            knownBadfiles.append(line)
        except Exception, e:
            print e
            print "File not found"
            sys.exit(0)
        try:
            getResultsFromFile(filePath, knownBadfiles, infile, outfile)
        except Exception,e:
            print e

            #with open(infile,"rb") as csvfile:
            #    reader = csv.reader(csvfile, delimiter=',')
            #    for row in reader:
            #            knownBadfiles.append(row)


    if filesize:
        global filename
        filename = filename or "SearchName1"
        filehashvalue = md5hash or sha1hash
        if len(str(filehashvalue)) == 32:
            getResultsOneEntry(filePath, filename, filesize, filehashvalue, outfile)
        elif len(str(filehashvalue)) == 40:
            getResultsOneEntry(filePath, filename, filesize, filehashvalue, outfile)
        else:
            print '\nThis is not a MD5 or SHA1 hash value!'
            print filehashvalue
            sys.exit(0)

    if md5hash:
        if not filesize:
            #global filename
            filename = filename or "SearchName1"
            HashOnlySearch(filePath, filename, md5hash, outfile)


    if sha1hash:
        if not filesize:
            #global filename
            filename = filename or "SearchName1"
            HashOnlySearch(filePath, filename, sha1hash, outfile)

    if hash_folder:
        putResultsIntoFile(hash_folder, outfile)

    if hash_harddrive == True:
        hashmode = 'md5_values'
        getHashValueForWholeHardDrive(filePath, hashmode, outfile)

    if hash_harddrivesha1 == True:
        hashmode = 'sha1_values'
        getHashValueForWholeHardDrive(filePath, hashmode, outfile)

if __name__ == '__main__':
    start_time = time.time()
    main()
    print "\nFinished."
    finish_time = int(time.time() - start_time)
    if finish_time < 120:
        print "  Completed in: %s seconds" % int(time.time() - start_time)
    elif finish_time < 3600:
        print "  Completed in: %s minutes" % int((time.time() - start_time) /60)
    else:
        print "  Completed in: %s hours" % int((time.time() - start_time) /3600)

#Open CSV File with sample hashes in comma delimited format using md5 or sha1:
#name    size    md5
#name    size    sha1


