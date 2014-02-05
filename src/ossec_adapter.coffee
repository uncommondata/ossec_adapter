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

  processLine: (line) ->
    @processAlert = new ProcessOssecAlert(line)
    event = @processAlert.run()
    @io.emit(event)

class ClientSocket
  constructor: ->
    console.log("Establishing socket.io connection... ") if debug
    #config = { key: "c07626c85eb3c13205b32005df582dbd", host: "uncommondata.herokuapp.com", port: 80 }
    config = {key: "", host: "localhost", port: 5000}
    url = "http://#{config.host}:#{config.port}"
    console.log url if debug
    @socket = io.connect(url)

  emit: (event) ->
    console.log "emit..."
    console.log(event) if debug
    @socket.emit('message', [event])

new OssecClient().run()
