WebSocket = require('ws')
fs = require('fs')
ProcessOssecAlert = require('./process_ossec_alert')

root = global
root.debug = false

class OssecClient
  readStdIn: ->
#    @ws = new ClientSocket
    stdin = process.openStdin()
    stdin.setEncoding 'utf8'
    stdin.on 'data', (ossec_syslog_alert) ->
      @processAlert = new ProcessOssecAlert(ossec_syslog_alert)
      @processAlert.run()

  # taken from stackoverflow
  readSyslogFile: (filePath) ->
    stream = fs.createReadStream(filePath, 'utf8')
    last = ""
    stream.on('data', (chunk) ->
      lines = (last + chunk).replace(/\\\|/g,'').split("\n")
      [lines...,last] = lines
      for logLine in lines
        @processAlert = new ProcessOssecAlert(logLine)
        @processAlert.run()
    )

class ClientSocket
  constructor: ->
    config = { key: "c07626c85eb3c13205b32005df582dbd", host: "uncommondata.herokuapp.com", port: 80 }
    new WebSocket("ws://#{config.host}:#{config.port}")
    console.log("Establishing websocket connection... ") if debug

o = new OssecClient()
o.readSyslogFile(process.argv[2])
#o.readStdIn()
