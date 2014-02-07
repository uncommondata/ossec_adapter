class EventBuilder
  constructor: (defaultParameters={ }) ->
    @event = {
      "account": defaultParameters.account or undefined,
      "event": {
        "device": { }
        "user": { }
        "payload": { }
      }
    }

  updateEvent: (parameters={ }) ->
    console.log(parameters) if global.debug

    # Event values
    @event.timestamp = parameters.timeStamp if parameters.timeStamp
    @event.name = parameters.description if parameters.description
    @event.event.severity = parameters.severity if parameters.severity

    # Device values
    @event.event.device.ip = parameters.device.ip if parameters.ip
    @event.event.device.hostname = parameters.device if parameters.device
    @event.event.device.identifier = parameters.device if parameters.identifier

    # User values / LDAP
    @event.event.user.identifier = parameters.identifier if parameters.identifier
    @event.event.user.email = parameters.email if parameters.email
    @event.event.user.firstName = parameters.firstName if parameters.firstName
    @event.event.user.lastName = parameters.lastName if parameters.lastName
    @event.event.user.position = parameters.position if parameters.position
    @event.event.user.login = parameters.login if parameters.login

    # Payload values
    @event.event.payload.body = parameters.message if parameters.message
    @event.event.payload.sourceIp = parameters.sourceIp if parameters.sourceIp
    @event.event.payload.sourcePort = parameters.sourcePort if parameters.sourceIp
    @event.event.payload.destinationIp = parameters.destinationIp if parameters.destinationIp
    @event.event.payload.destinationPort = parameters.destinationPort if parameters.destinationPort
    @event.event.payload.description = parameters.description if parameters.description
    @event.event.payload.device = parameters.device if parameters.device
    @event.event.payload.ruleid = parameters.ruleId if parameters.ruleid
    @event.event.payload.component = parameters.component if parameters.component
    @event.event.payload.classification = parameters.classification if parameters.classification
    @event.event.payload.message = parameters.message if parameters.message
    @event.event.payload.fileName = parameters.fileName if parameters.fileName
    @event.event.payload.newMd5 = parameters.newMd5 if parameters.newMd5
    @event.event.payload.oldMd5 = parameters.oldMd5 if parameters.oldMd5
    @event.event.payload.newSha1 = parameters.newSha1 if parameters.newSha1
    @event.event.payload.oldSha1 = parameters.oldSha1 if parameters.oldSha1
    @event.event.payload.domains = parameters.domains if parameters.domains
    @event.event.payload.emails = parameters.emails if parameters.emails
    @event.event.payload.ipAddresses = parameters.ipAddrs if parameters.ipAddrs
    @event.event.payload.logins = parameters.users if parameters.users

module.exports = EventBuilder
