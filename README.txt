

                          // Match The Hash//

              Matches The Hash values to files on a machine.


    ~ What is Match The Hash?

	Python script that can help find malware on your machine.
        Sample data is created as: <name>,<size>,<MD5>
        That data is then used to search other machines.  

        The search runs much faster if file size and hash values are included.
	Name is ignored, file size is matched first,
	then hashes and attempts to match the hash values. 


    ~ Examples

        Search your whole hard drive with hash only.
	Match_The_Hash.py -md5 d378bffb70923139d6a4f546864aa61c

	It will go much faster if you include file size.
	Match_The_Hash.py -size 179712 -md5 d378bffb70923139d6a4f546864aa61c

	Name can be included but it is ignored in the search.
	-name malware1.exe -size 179712 -md5 d378bffb70923139d6a4f546864aa61c	

        Create a large sample of data from all files in a folder.
	-hf = hash folder
	Match_The_Hash.py -hf <Path_to_folder> -o samples.csv

	Then use this folder as your input. -i
	Match_The_Hash.py -i samples.csv -o results.csv


    ~ Notes

        Compiled using pyinstaller.

	If no output file is assigned using -o,
	Output file Match_The_Hash.csv will be created at current working directory.

	Match_The_Hash.py    = Works on Windows,Linux,Mac
	Match_The_Hash32.exe = 32bit Windows
	Match_The_Hash64.exe = 64bit Windows

        The example is notepad.exe to test if it's working on Windows 7 machine.
        Match_The_Hash.py -size 179712 -md5 d378bffb70923139d6a4f546864aa61c



    ~ Usage


	usage: Match_The_Hash.py [-h] [-name FILENAME] [-size FILESIZE]
        	                    [-md5 MD5HASH] [-sha1 SHA1HASH] [-hf HASH_FOLDER]
                	            [-hhd] [-hhdsha1] [-p PATH] [-i INFILE]
                        	    [-o OUTFILE]

	Matches The Hash values to files on a machine.

	optional arguments:
	  -h, --help       show this help message and exit
	  -name FILENAME   Name of single file to search
	  -size FILESIZE   Size of file to search. Faster than hash only search.
	  -md5 MD5HASH     MD5 hash value to search.
	  -sha1 SHA1HASH   SHA1 hash value to search.
	  -hf HASH_FOLDER  Hash contents of a folder.
	  -hhd             Hash contents of an entire hard drive: MD5.
	  -hhdsha1         Hash contents of an entire hard drive: SHA1.
	  -p PATH          Path to start in, else search whole disk.
	  -i INFILE        CSV or text file in this format 'malwarename1.exe,size,MD5'
	                   or SHA1 hash value.'
	  -o OUTFILE       Output file.

	MatchTheHash goes much faster if file size is included.
	  File sizes are matched first and then hash values.

	Examples:
	  -size 179712 -md5 d378bffb70923139d6a4f546864aa61c
	  -hf folder_path -o samples.csv (Hash folder that contains malware samples.)
	   -i samples.csv -o results.csv (Sample data is input to search for matches.)


  