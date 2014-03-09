optimist = require 'optimist'
io = require('socket.io-client')
fs = require('fs')
ProcessOssecJsonAlert = require('./parsers/process_ossec_json_alert')

root = global
root.debug = true

class OssecClient
  run: ->
    @io = new ClientSocket()
    optimist.usage 'Uncommon Data OSSEC Adapter'
    optimist.options 'a',
      alias: "alerts"
      describe: 'Read OSSEC alert.log file (expecting default format)'
      default: process.argv.f
    optimist.options 'f',
      alias: "file"
      describe: 'Syslog file containing OSSEC JSON alerts'
      default: process.argv.f
    optimist.options 's',
      alias: "STDIN"
      describe: 'Read from STDIN (expecting Syslog file w/OSSEC JSON alerts)'
    optimist.options 'h',
      alias: "help"
      describe: 'Show this message'
    argv = optimist.argv

    if argv.f
      @readFromSyslogFile(argv.f)
    else if argv.s
      @readFromStdIn()
    else if argv.a
      @readFromAlertsFile(argv.a)
    else
      console.log optimist.help()

  readFromStdIn: ->
    stdin = process.openStdin()
    stdin.setEncoding 'utf8'
    stdin.on 'data', (ossec_syslog_alert) =>
      @processLine(ossec_syslog_alert,"syslog")

  # next snippet from stackoverflow
  readFromSyslogFile: (filePath) ->
    stream = fs.createReadStream(filePath, 'utf8')
    last = ""
    stream.on 'data', (chunk) =>
      lines = (last + chunk).replace(/\\\|/g,'').split("\n")
      [lines...,last] = lines
      @processLine(logLine,"syslog") for logLine in lines

  readFromAlertsFile: (filePath) ->
    #for line in fs.readFileSync(filePath)

  processLine: (logLine, format) ->
    if format == "syslog"
      @processAlert = new ProcessOssecJsonAlert(logLine)
      event = @processAlert.run()
    else if format == "ossec"
      @processAlert = new ProcessOssecAlertLog(logLine)
      event = @processAlert.run()
    if event
      @io.emit(event)

class ClientSocket
  constructor: ->
    @buffer = []
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

    @socket.on "disconnect", =>
      @ready = false

  emit: (event) ->
    if @ready
      console.log "emit..."
      console.log(event) if debug
      @socket.emit('message', [event])
      while @buffer.length > 0
        @socket.emit('message', [@buffer.pop])
    else
      @buffer.push event
      console.log ("error: socket not ready, adding event to buffer, total # buffered alerts = " + @buffer.length)

new OssecClient().run()