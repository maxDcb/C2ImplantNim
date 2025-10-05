import std/unittest
import std/json
import std/base64
import std/os
import std/osproc
import std/strutils
import std/tempfiles
import ".."/Beacon

proc encodeField(value: string): string =
  if value.len == 0:
    return value
  encode(value.toOpenArrayByte(0, value.high))


proc enqueueTask(
    beacon: Beacon,
    instruction: string,
    uuid: string,
    cmd: string = emptyString,
    args: string = emptyString,
    data: string = emptyString,
    inputFile: string = emptyString,
    outputFile: string = emptyString
) =
  var session = newJObject()
  session[instructionMsgTag] = %instruction
  session[uuidMsgTag] = %uuid
  if cmd.len > 0:
    session[cmdMsgTag] = %cmd
  if args.len > 0:
    session[argsTag] = %args
  if data.len > 0:
    session[dataTag] = %encodeField(data)
  if inputFile.len > 0:
    session[inputFileTag] = %encodeField(inputFile)
  if outputFile.len > 0:
    session[outputFileTag] = %encodeField(outputFile)

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


proc setupBeacon(): Beacon =
  var beacon: Beacon
  new(beacon)
  beacon.initBeacon()
  beacon


proc runShellCommand(command: string): string =
  if command.len == 0:
    return emptyString
  try:
    result = execProcess(shellExecutable, args=[shellFlag, command], options={poUsePath})
  except OSError:
    result = commandExecutionFailureMessage


proc quoteForCommand(path: string): string =
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

suite "Beacon":
  test "initBeacon initializes defaults":
    let beacon = setupBeacon()

    check beacon.beaconHash.len == 32
    check beacon.sleepTimeMs == 1000
    check beacon.listenerHash == emptyString
    check beacon.taskResults.len == 0
    check beacon.processId.len > 0
    check beacon.hostname.len > 0
    check beacon.privilege in [privilegeHigh, privilegeLow]
    check beacon.xorKey == emptyString

  test "execInstruction handles loadmodule instruction":
    let beacon = setupBeacon()

    enqueueTask(beacon, instructionLoadModule, uuid = "task-loadmodule")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionLoadModule
    check result.returnValue == loadModuleNotRequiredMessage

  test "execInstruction handles ls instruction":
    let beacon = setupBeacon()
    let tempDir = createTempDir("beacon_ls")
    let tempFile = joinPath(tempDir, "entry.txt")
    writeFile(tempFile, "content")
    let expected = runShellCommand(listDirectoryCommand & quoteForCommand(tempDir))

    enqueueTask(beacon, instructionLs, uuid = "task-ls", cmd = tempDir)

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionLs
    check result.returnValue == expected

    removeFile(tempFile)
    removeDir(tempDir)

  test "execInstruction handles listdirectory instruction":
    let beacon = setupBeacon()
    let tempDir = createTempDir("beacon_listdirectory")
    let tempFile = joinPath(tempDir, "entry.txt")
    writeFile(tempFile, "content")
    let expected = runShellCommand(listDirectoryCommand & quoteForCommand(tempDir))

    enqueueTask(beacon, instructionListDirectory, uuid = "task-listdirectory", cmd = tempDir)

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionListDirectory
    check result.returnValue == expected

    removeFile(tempFile)
    removeDir(tempDir)

  test "execInstruction handles ps instruction":
    let beacon = setupBeacon()
    let expected = runShellCommand(processListCommand)

    enqueueTask(beacon, instructionPs, uuid = "task-ps")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionPs
    check result.returnValue == expected

  test "execInstruction handles listprocesses instruction":
    let beacon = setupBeacon()
    let expected = runShellCommand(processListCommand)

    enqueueTask(beacon, instructionListProcesses, uuid = "task-listprocesses")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionListProcesses
    check result.returnValue == expected

  test "execInstruction handles cd instruction":
    let beacon = setupBeacon()
    let originalDir = getCurrentDir()
    let newDir = createTempDir("beacon_cd")

    enqueueTask(beacon, instructionCd, uuid = "task-cd", cmd = newDir)

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionCd
    check getCurrentDir() == newDir
    check result.returnValue == newDir

    setCurrentDir(originalDir)
    removeDir(newDir)

  test "execInstruction handles changedirectory instruction":
    let beacon = setupBeacon()
    let originalDir = getCurrentDir()

    enqueueTask(beacon, instructionChangeDirectory, uuid = "task-changedir")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionChangeDirectory
    check result.returnValue == missingPathMessage
    check getCurrentDir() == originalDir

  test "execInstruction handles pwd instruction":
    let beacon = setupBeacon()
    let expected = getCurrentDir()

    enqueueTask(beacon, instructionPwd, uuid = "task-pwd")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionPwd
    check result.returnValue == expected

  test "execInstruction handles printworkingdirectory instruction":
    let beacon = setupBeacon()
    let expected = getCurrentDir()

    enqueueTask(beacon, instructionPrintWorkingDirectory, uuid = "task-pwd-alias")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionPrintWorkingDirectory
    check result.returnValue == expected

  test "execInstruction handles download instruction":
    let beacon = setupBeacon()
    let tempDir = createTempDir("beacon_download")
    let filePath = joinPath(tempDir, "download.txt")
    let fileContent = "download-content"
    writeFile(filePath, fileContent)

    enqueueTask(beacon, instructionDownload, uuid = "task-download", inputFile = filePath)

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionDownload
    check result.returnValue == okMessage
    check result.data == fileContent
    check result.inputFile == filePath

    removeFile(filePath)
    removeDir(tempDir)

  test "execInstruction handles upload instruction":
    let beacon = setupBeacon()
    let tempDir = createTempDir("beacon_upload")
    let targetPath = joinPath(tempDir, "uploaded.txt")
    let content = "upload-content"

    enqueueTask(
      beacon,
      instructionUpload,
      uuid = "task-upload",
      outputFile = targetPath,
      data = content
    )

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionUpload
    check result.returnValue == okMessage
    check result.data == content
    check fileExists(targetPath)
    check readFile(targetPath) == content

    removeFile(targetPath)
    removeDir(tempDir)

  test "execInstruction handles run instruction":
    let beacon = setupBeacon()
    let expected = runShellCommand("echo run-instruction")

    enqueueTask(beacon, instructionRun, uuid = "task-run", cmd = "echo", args = "run-instruction")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionRun
    check result.returnValue == expected

  test "execInstruction handles shell instruction":
    let beacon = setupBeacon()
    let expected = runShellCommand("echo shell-instruction")

    enqueueTask(beacon, instructionShell, uuid = "task-shell", cmd = "echo", args = "shell-instruction")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionShell
    check result.returnValue == expected

  test "execInstruction handles powershell instruction":
    let beacon = setupBeacon()

    enqueueTask(beacon, instructionPowershell, uuid = "task-powershell", cmd = "Write-Host hi")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionPowershell
    when defined(windows):
      var expected = emptyString
      try:
        expected = execProcess(
          "powershell",
          args=["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "Write-Host hi"],
          options={poUsePath}
        )
      except OSError:
        expected = commandExecutionFailureMessage
      check result.returnValue == expected
    else:
      check result.returnValue == operationNotSupportedMessage

  test "execInstruction handles cat instruction":
    let beacon = setupBeacon()
    let tempDir = createTempDir("beacon_cat")
    let filePath = joinPath(tempDir, "cat.txt")
    let fileContent = "cat-content"
    writeFile(filePath, fileContent)

    enqueueTask(beacon, instructionCat, uuid = "task-cat", inputFile = filePath)

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionCat
    check result.returnValue == fileContent

    removeFile(filePath)
    removeDir(tempDir)

  test "execInstruction handles mkdir instruction":
    let beacon = setupBeacon()
    let baseDir = createTempDir("beacon_mkdir")
    let newDir = joinPath(baseDir, "created")

    enqueueTask(beacon, instructionMkDir, uuid = "task-mkdir", cmd = newDir)

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionMkDir
    check result.returnValue == okMessage
    check dirExists(newDir)

    removeDir(newDir)
    removeDir(baseDir)

  test "execInstruction handles remove instruction":
    let beacon = setupBeacon()
    let tempDir = createTempDir("beacon_remove")
    let filePath = joinPath(tempDir, "remove.txt")
    writeFile(filePath, "remove-me")

    enqueueTask(beacon, instructionRemove, uuid = "task-remove", cmd = filePath)

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionRemove
    check result.returnValue == okMessage
    check not fileExists(filePath)

    removeDir(tempDir)

  test "execInstruction handles killprocess instruction":
    let beacon = setupBeacon()

    enqueueTask(beacon, instructionKillProcess, uuid = "task-kill", cmd = "not-an-int")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionKillProcess
    check result.returnValue == invalidProcessIdMessage

  test "execInstruction handles tree instruction":
    let beacon = setupBeacon()
    let baseDir = createTempDir("beacon_tree")
    let nestedDir = joinPath(baseDir, "nested")
    let nestedFile = joinPath(nestedDir, "file.txt")
    createDir(nestedDir)
    writeFile(nestedFile, "content")

    enqueueTask(beacon, instructionTree, uuid = "task-tree", cmd = baseDir)

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionTree
    check result.returnValue.contains("nested")
    check result.returnValue.contains("file.txt")

    removeFile(nestedFile)
    removeDir(nestedDir)
    removeDir(baseDir)

  test "execInstruction handles getenv instruction":
    let beacon = setupBeacon()
    putEnv("BEACON_TEST_ENV", "env-value")

    enqueueTask(beacon, instructionGetEnv, uuid = "task-getenv", cmd = "BEACON_TEST_ENV")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionGetEnv
    check result.returnValue == "env-value"

  test "execInstruction handles whoami instruction":
    let beacon = setupBeacon()
    let expected = runShellCommand("whoami").strip()

    enqueueTask(beacon, instructionWhoami, uuid = "task-whoami")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionWhoami
    check result.returnValue == expected

  test "execInstruction handles netstat instruction":
    let beacon = setupBeacon()
    let expected = runShellCommand("netstat -an")

    enqueueTask(beacon, instructionNetstat, uuid = "task-netstat")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionNetstat
    check result.returnValue == expected

  test "execInstruction handles ipconfig instruction":
    let beacon = setupBeacon()
    let primary = runShellCommand("ip addr show")
    let expected = if primary.len > 0: primary else: runShellCommand("ifconfig -a")

    enqueueTask(beacon, instructionIpConfig, uuid = "task-ipconfig")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionIpConfig
    check result.returnValue == expected

  test "execInstruction handles enumerateshares instruction":
    let beacon = setupBeacon()

    enqueueTask(beacon, instructionEnumerateShares, uuid = "task-enumerateshares")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionEnumerateShares
    when defined(windows):
      let expected = runShellCommand("net share")
      check result.returnValue == expected
    else:
      check result.returnValue == operationNotSupportedMessage

  test "execInstruction handles sleep instruction":
    let beacon = setupBeacon()

    enqueueTask(beacon, instructionSleep, uuid = "task-sleep", cmd = "2")

    beacon.execInstruction()

    check beacon.sleepTimeMs == 2000
    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionSleep
    check result.returnValue == okMessage

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

  test "execInstruction handles invalid sleep value":
    let beacon = setupBeacon()
    let originalSleep = beacon.sleepTimeMs

    enqueueTask(beacon, instructionSleep, uuid = "task-sleep-invalid", cmd = "not-a-number")

    beacon.execInstruction()

    check beacon.sleepTimeMs == originalSleep
    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.instruction == instructionSleep
    check result.returnValue == invalidSleepValueMessage

  test "execInstruction handles unknown instruction":
    let beacon = setupBeacon()

    enqueueTask(beacon, "nonsense", uuid = "task-unknown")

    beacon.execInstruction()

    check beacon.taskResults.len == 1
    let result = beacon.taskResults[0]
    check result.returnValue == unknownInstructionMessage
