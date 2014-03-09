// Generated by CoffeeScript 1.6.3
(function() {
  var ClientSocket, io;

  io = require('socket.io-client');

  ClientSocket = (function() {
    function ClientSocket() {
      var config, url,
        _this = this;
      this.buffer = [];
      if (debug) {
        console.log("Establishing socket.io connection... ");
      }
      config = {
        key: "56dd2065956030fe1c6016dc04917ded",
        host: "localhost",
        port: 5000
      };
      url = "http://" + config.host + ":" + config.port;
      this.ready = false;
      this.socket = io.connect(url);
      this.socket.on("connect", function() {
        console.log("connection established");
        return _this.socket.emit("identify", config.key, function(response) {
          if (response === "ok") {
            console.log("identity verified");
            return _this.ready = true;
          } else {
            return console.log("error, invalid api key");
          }
        });
      });
      this.socket.on("disconnect", function() {
        return _this.ready = false;
      });
    }

    ClientSocket.prototype.emit = function(event) {
      var _results;
      if (this.ready) {
        console.log("emit...");
        if (debug) {
          console.log(event);
        }
        this.socket.emit('message', [event]);
        _results = [];
        while (this.buffer.length > 0) {
          _results.push(this.socket.emit('message', [this.buffer.pop]));
        }
        return _results;
      } else {
        this.buffer.push(event);
        return console.log("error: socket not ready, adding event to buffer, total # buffered alerts = " + this.buffer.length);
      }
    };

    return ClientSocket;

  })();

  module.exports = ClientSocket;

}).call(this);