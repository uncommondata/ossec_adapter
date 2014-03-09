io = require('socket.io-client')

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

module.exports = ClientSocket
