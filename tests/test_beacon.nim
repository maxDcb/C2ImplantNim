import std/unittest
import std/json
import std/base64
import ".."/Beacon

proc enqueueTask(beacon: Beacon, instruction: string, uuid: string, cmd: string = emptyString, args: string = emptyString) =
  var session = newJObject()
  session[instructionMsgTag] = %instruction
  session[uuidMsgTag] = %uuid
  if cmd.len > 0:
    session[cmdMsgTag] = %cmd
  if args.len > 0:
    session[argsTag] = %args

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
