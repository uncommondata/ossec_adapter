optimist = require 'optimist'
io = require('socket.io-client')
fs = require('fs')
ProcessOssecAlert = require('./process_ossec_alert')

root = global
root.debug = true

class OssecClient
  run: ->
    @io = new ClientSocket()
    optimist.usage 'Uncommon Data OSSEC Adapter'
    optimist.options 'f',
      describe : 'Syslog file containing OSSEC JSON alerts'
      default : process.argv.f
    optimist.options 's',
      describe : 'Read from STDIN (expecting Syslog file w/OSSEC JSON alerts)'
    optimist.options 'h',
      describe : 'Show this message'
    argv = optimist.argv

    if argv.f
      @readFromSyslogFile(argv.f)
    else if argv.s
      @readFromStdIn()
    else
      console.log optimist.help()

  readFromStdIn: ->
    stdin = process.openStdin()
    stdin.setEncoding 'utf8'
    stdin.on 'data', (ossec_syslog_alert) =>
      @processLine ossec_syslog_alert

  # taken from stackoverflow
  readFromSyslogFile: (filePath) ->
    stream = fs.createReadStream(filePath, 'utf8')
    last = ""
    stream.on 'data', (chunk) =>
      lines = (last + chunk).replace(/\\\|/g,'').split("\n")
      [lines...,last] = lines
      @processLine(logLine) for logLine in lines

  processLine: (logLine) ->
    @processAlert = new ProcessOssecAlert(logLine)
    event = @processAlert.run()
    @io.emit(event)

class ClientSocket
  constructor: ->
    console.log("Establishing socket.io connection... ") if debug
    #config = { key: "c07626c85eb3c13205b32005df582dbd", host: "uncommondata.herokuapp.com", port: 80 }
    config = {key: "56dd2065956030fe1c6016dc04917ded", host: "localhost", port: 5000}
    url = "http://#{config.host}:#{config.port}"
    @ready = false
    @socket = io.connect(url)
    @socket.on "connect", =>
      console.log "connection established"
      @socket.emit "identify", config.key, (response) =>
        if response == "ok"
          console.log "identity verified"
          @ready = true
        else
          console.log "error, invalid api key"

  emit: (event) ->
    if @ready
      console.log "emit..."
      console.log(event) if debug
      @socket.emit('message', [event])
    else
      console.log "error: not ready; TODO - implement buffering..."

new OssecClient().run()
