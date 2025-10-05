import std/unittest
import std/json
import std/base64
import std/os
import std/strutils
import std/osproc
import std/times
import ".."/Beacon

proc uniqueTempPath(prefix: string): string =
  let timestamp = int(epochTime())
  joinPath(getTempDir(), prefix & "_" & $getpid() & "_" & $timestamp)


proc removePathRecursively(path: string) =
  if fileExists(path) or symlinkExists(path):
    removeFile(path)
  elif dirExists(path):
    for kind, entry in walkDir(path):
      case kind
      of pcFile, pcLinkToFile:
        removeFile(entry)
      of pcDir, pcLinkToDir:
        removePathRecursively(entry)
      else:
        discard
    removeDir(path)


proc enqueueTask(
    beacon: Beacon,
    instruction: string,
    uuid: string,
    cmd: string = emptyString,
    args: string = emptyString,
    inputFile: string = emptyString,
    outputFile: string = emptyString,
    data: string = emptyString
) =
  var session = newJObject()
  session[instructionMsgTag] = %instruction
  session[uuidMsgTag] = %uuid
  if cmd.len > 0:
    session[cmdMsgTag] = %cmd
  if args.len > 0:
    session[argsTag] = %args
  if inputFile.len > 0:
    session[inputFileTag] = %encodeString(inputFile)
  if outputFile.len > 0:
    session[outputFileTag] = %encodeString(outputFile)
  if data.len > 0:
    session[dataTag] = %encodeString(data)

  var sessions = newJArray()
  sessions.add(session)

  var bundle = newJObject()
  bundle[beaconHashMsgTag] = %beacon.beaconHash
  bundle[sessionsMsgTag] = sessions

  var payload = newJArray()
  payload.add(bundle)

  let serialized = $payload
  let encoded = encode(serialized.toOpenArrayByte(0, serialized.high))

  beacon.cmdToTasks(encoded)


proc executeInstruction(
    instruction: string,
    cmd: string = emptyString,
    args: string = emptyString,
    inputFile: string = emptyString,
    outputFile: string = emptyString,
    data: string = emptyString
): (Beacon, C2Message) =
  var beacon: Beacon
  new(beacon)
  beacon.initBeacon()

  enqueueTask(
    beacon,
    instruction,
    uuid = "task-" & instruction,
    cmd = cmd,
    args = args,
    inputFile = inputFile,
    outputFile = outputFile,
    data = data
  )

  beacon.execInstruction()

  if beacon.taskResults.len == 0:
    (beacon, C2Message())
  else:
    (beacon, beacon.taskResults[0])

suite "Beacon":
  test "initBeacon initializes defaults":
    var beacon: Beacon
    new(beacon)
    beacon.initBeacon()

    check beacon.beaconHash.len == 32
    check beacon.sleepTimeMs == 1000
    check beacon.listenerHash == emptyString
    check beacon.taskResults.len == 0
    check beacon.processId.len > 0
    check beacon.hostname.len > 0
    check beacon.privilege in [privilegeHigh, privilegeLow]
    check beacon.xorKey == emptyString

  test "execInstruction handles sleep instruction":
    var beacon: Beacon
    new(beacon)
    beacon.initBeacon()

    enqueueTask(beacon, instructionSleep, uuid = "task-1", cmd = "2")

    beacon.execInstruction()

    check beacon.sleepTimeMs == 2000
    check beacon.taskResults.len == 1
    check beacon.taskResults[0].instruction == instructionSleep
    check beacon.taskResults[0].returnValue == okMessage

    let encodedResults = beacon.taskResultsToCmd()
    check encodedResults.len > 0
    check beacon.taskResults.len == 0

    let decoded = decode(encodedResults)
    let transformed = xorEncode(beacon.xorKey, decoded)
    let payload = toString(transformed)
    let jsonPayload = parseJson(payload)

    check jsonPayload.len == 1
    let sessionBundle = jsonPayload[0]
    check sessionBundle.hasKey(sessionsMsgTag)
    let sessions = sessionBundle[sessionsMsgTag]
    check sessions.len == 1
    let session = sessions[0]
    check session[instructionMsgTag].getStr() == instructionSleep
    let encodedReturnValue = session[returnValueTag].getStr()
    check decode(encodedReturnValue) == okMessage

  test "execInstruction handles unknown instruction":
    var beacon: Beacon
    new(beacon)
    beacon.initBeacon()

    enqueueTask(beacon, "nonsense", uuid = "task-2")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    check beacon.taskResults[0].returnValue == unknownInstructionMessage

  test "execInstruction handles load module instruction":
    let (_, result) = executeInstruction(instructionLoadModule)

    check result.returnValue == loadModuleNotRequiredMessage

  test "execInstruction handles directory listing instructions":
    let tempDir = uniqueTempPath("beacon_ls")
    createDir(tempDir)
    defer:
      if dirExists(tempDir):
        removePathRecursively(tempDir)

    let filePath = joinPath(tempDir, "sample.txt")
    writeFile(filePath, "content")

    for instruction in [instructionLs, instructionListDirectory]:
      let (_, result) = executeInstruction(instruction, cmd = tempDir)
      check result.returnValue.contains("sample.txt")

  test "execInstruction handles process listing instructions":
    for instruction in [instructionPs, instructionListProcesses]:
      let (_, result) = executeInstruction(instruction)
      check result.returnValue.contains("PID") or result.returnValue.contains("STAT")

  test "execInstruction handles change directory instructions":
    let originalDir = getCurrentDir()
    let tempDir = uniqueTempPath("beacon_cd")
    createDir(tempDir)
    defer:
      setCurrentDir(originalDir)
      if dirExists(tempDir):
        removePathRecursively(tempDir)

    for instruction in [instructionCd, instructionChangeDirectory]:
      setCurrentDir(originalDir)
      let (_, result) = executeInstruction(instruction, cmd = tempDir)
      check result.returnValue == tempDir
      check getCurrentDir() == tempDir

  test "execInstruction handles print working directory instructions":
    let originalDir = getCurrentDir()
    for instruction in [instructionPwd, instructionPrintWorkingDirectory]:
      let (_, result) = executeInstruction(instruction)
      check result.returnValue == originalDir

  test "execInstruction handles download instruction":
    let tempDir = uniqueTempPath("beacon_download")
    createDir(tempDir)
    defer:
      if dirExists(tempDir):
        removePathRecursively(tempDir)

    let filePath = joinPath(tempDir, "download.txt")
    let fileContent = "download-content"
    writeFile(filePath, fileContent)

    let (_, result) = executeInstruction(instructionDownload, inputFile = filePath)

    check result.returnValue == okMessage
    check result.data == fileContent

  test "execInstruction handles upload instruction":
    let tempDir = uniqueTempPath("beacon_upload")
    createDir(tempDir)
    defer:
      if dirExists(tempDir):
        removePathRecursively(tempDir)

    let filePath = joinPath(tempDir, "upload.txt")
    let content = "uploaded"

    let (_, result) = executeInstruction(instructionUpload, outputFile = filePath, data = content)

    check result.returnValue == okMessage
    check readFile(filePath) == content

  test "execInstruction handles run instruction":
    let (_, result) = executeInstruction(instructionRun, cmd = "echo run-test")
    check result.returnValue.strip() == "run-test"

  test "execInstruction handles shell instruction":
    let (_, result) = executeInstruction(instructionShell, cmd = "echo shell-test")
    check result.returnValue.strip() == "shell-test"

  test "execInstruction handles powershell instruction":
    let (_, result) = executeInstruction(instructionPowershell, cmd = "Write-Host test")
    when defined(windows):
      check result.returnValue.len >= 0
    else:
      check result.returnValue == operationNotSupportedMessage

  test "execInstruction handles cat instruction":
    let tempDir = uniqueTempPath("beacon_cat")
    createDir(tempDir)
    defer:
      if dirExists(tempDir):
        removePathRecursively(tempDir)

    let filePath = joinPath(tempDir, "cat.txt")
    let fileContent = "cat-content"
    writeFile(filePath, fileContent)

    let (_, result) = executeInstruction(instructionCat, inputFile = filePath)

    check result.returnValue == fileContent

  test "execInstruction handles mkdir instruction":
    let tempDir = uniqueTempPath("beacon_mkdir")
    defer:
      if dirExists(tempDir):
        removePathRecursively(tempDir)

    let (_, result) = executeInstruction(instructionMkDir, cmd = tempDir)

    check dirExists(tempDir)
    check result.returnValue == okMessage

  test "execInstruction handles remove instruction":
    let tempDir = uniqueTempPath("beacon_remove")
    createDir(tempDir)
    let filePath = joinPath(tempDir, "remove.txt")
    writeFile(filePath, "data")

    let (_, result) = executeInstruction(instructionRemove, cmd = filePath)

    check not fileExists(filePath)
    check result.returnValue == okMessage

    if dirExists(tempDir):
      removePathRecursively(tempDir)

  test "execInstruction handles kill process instruction":
    var process = startProcess("sleep", ["30"])
    let pid = $processID(process)
    defer:
      if process.running:
        terminate(process)
      close(process)

    let (_, result) = executeInstruction(instructionKillProcess, cmd = pid)

    check result.returnValue == okMessage
    waitForExit(process)

  test "execInstruction handles tree instruction":
    let rootDir = uniqueTempPath("beacon_tree")
    createDir(rootDir)
    let childDir = joinPath(rootDir, "child")
    createDir(childDir)
    let filePath = joinPath(childDir, "file.txt")
    writeFile(filePath, "data")
    defer:
      if dirExists(rootDir):
        removePathRecursively(rootDir)

    let (_, result) = executeInstruction(instructionTree, cmd = rootDir)

    check result.returnValue.contains("child")
    check result.returnValue.contains("file.txt")

  test "execInstruction handles getenv instruction":
    let expected = getEnv("PATH")
    let (_, result) = executeInstruction(instructionGetEnv, cmd = "PATH")

    check result.returnValue == expected or (expected.len == 0 and result.returnValue == environmentVariableNotFoundMessage)

  test "execInstruction handles whoami instruction":
    let (_, result) = executeInstruction(instructionWhoami)

    check result.returnValue.len > 0

  test "execInstruction handles netstat instruction":
    let (_, result) = executeInstruction(instructionNetstat)

    check result.returnValue == commandExecutionFailureMessage or result.returnValue.len > 0

  test "execInstruction handles ipconfig instruction":
    let (_, result) = executeInstruction(instructionIpConfig)

    check result.returnValue == commandExecutionFailureMessage or result.returnValue.len > 0

  test "execInstruction handles enumerate shares instruction":
    let (_, result) = executeInstruction(instructionEnumerateShares)

    when defined(windows):
      check result.returnValue.len > 0
    else:
      check result.returnValue == operationNotSupportedMessage
