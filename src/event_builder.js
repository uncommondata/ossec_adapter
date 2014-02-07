// Generated by CoffeeScript 1.6.3
(function() {
  var EventBuilder;

  EventBuilder = (function() {
    function EventBuilder(defaultParameters) {
      if (defaultParameters == null) {
        defaultParameters = {};
      }
      this.event = {
        "account": defaultParameters.account || void 0,
        "event": {
          "device": {},
          "user": {},
          "payload": {}
        }
      };
    }

    EventBuilder.prototype.updateEvent = function(parameters) {
      if (parameters == null) {
        parameters = {};
      }
      console.log(parameters);
      if (parameters.timeStamp) {
        this.event.timestamp = parameters.timeStamp;
      }
      if (parameters.description) {
        this.event.name = parameters.description;
      }
      if (parameters.severity) {
        this.event.event.severity = parameters.severity;
      }
      if (parameters.ip) {
        this.event.event.device.ip = parameters.device.ip;
      }
      if (parameters.device) {
        this.event.event.device.hostname = parameters.device;
      }
      if (parameters.identifier) {
        this.event.event.device.identifier = parameters.device;
      }
      if (parameters.identifier) {
        this.event.event.user.identifier = parameters.identifier;
      }
      if (parameters.email) {
        this.event.event.user.email = parameters.email;
      }
      if (parameters.firstName) {
        this.event.event.user.firstName = parameters.firstName;
      }
      if (parameters.lastName) {
        this.event.event.user.lastName = parameters.lastName;
      }
      if (parameters.position) {
        this.event.event.user.position = parameters.position;
      }
      if (parameters.login) {
        this.event.event.user.login = parameters.login;
      }
      if (parameters.message) {
        this.event.event.payload.body = parameters.message;
      }
      if (parameters.sourceIp) {
        this.event.event.payload.sourceIp = parameters.sourceIp;
      }
      if (parameters.sourceIp) {
        this.event.event.payload.sourcePort = parameters.sourcePort;
      }
      if (parameters.destinationIp) {
        this.event.event.payload.destinationIp = parameters.destinationIp;
      }
      if (parameters.destinationPort) {
        this.event.event.payload.destinationPort = parameters.destinationPort;
      }
      if (parameters.description) {
        this.event.event.payload.description = parameters.description;
      }
      if (parameters.device) {
        this.event.event.payload.device = parameters.device;
      }
      if (parameters.ruleid) {
        this.event.event.payload.ruleid = parameters.ruleId;
      }
      if (parameters.component) {
        this.event.event.payload.component = parameters.component;
      }
      if (parameters.classification) {
        this.event.event.payload.classification = parameters.classification;
      }
      if (parameters.message) {
        this.event.event.payload.message = parameters.message;
      }
      if (parameters.fileName) {
        this.event.event.payload.fileName = parameters.fileName;
      }
      if (parameters.newMd5) {
        this.event.event.payload.newMd5 = parameters.newMd5;
      }
      if (parameters.oldMd5) {
        this.event.event.payload.oldMd5 = parameters.oldMd5;
      }
      if (parameters.newSha1) {
        this.event.event.payload.newSha1 = parameters.newSha1;
      }
      if (parameters.oldSha1) {
        this.event.event.payload.oldSha1 = parameters.oldSha1;
      }
      if (parameters.domains) {
        this.event.event.payload.domains = parameters.domains;
      }
      if (parameters.emails) {
        this.event.event.payload.emails = parameters.emails;
      }
      if (parameters.ipAddrs) {
        this.event.event.payload.ipAddresses = parameters.ipAddrs;
      }
      if (parameters.users) {
        return this.event.event.payload.logins = parameters.users;
      }
    };

    return EventBuilder;

  })();

  module.exports = EventBuilder;

}).call(this);

/*
//@ sourceMappingURL=event_builder.map
*/