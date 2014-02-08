EventBuilder = require('./event_builder')
OssecAlertAttributesExtractor = require('./extractors/ossec_alert_attributes_extractor')
VariableExtractor = require('./extractors/variable_extractor')
UserExtractor = require('./extractors/user_extractor')
GetMeta = require('./extractors/get_meta')

class ProcessOssecAlert
  constructor: (@ossecSyslogAlert) ->
    console.log("Found OSSEC alert: " + @ossecSyslogAlert) if debug
    @event = new EventBuilder()

  run: ->
    @extractJsonBlock()
    if @ossecAlert?
      @process()
      @updateEvent()
      @event.event
    else
      console.log("Log line does not contain an OSSEC alert?: " + @ossecSyslogAlert) if debug
      return false

  extractJsonBlock: ->
    ossecJsonPattern = /([A-Z][a-z]{2}\s\d{1,2}\s\d{2}:\d{2}:\d{2}).*ossec:\s({\s\"crit\"\:\s\d{1,2}\,\s\"id\"\:\s\d+.*\})/
    match = @ossecSyslogAlert.match ossecJsonPattern
    @timeStamp = match[1] if match
    @ossecAlert = JSON.parse(match[2]) if match

  process: ->
    @attributesExtractor = new OssecAlertAttributesExtractor(@logHeader, @ossecAlert, @event)
    @attributes = @attributesExtractor.run()
    @variableExtractor = new VariableExtractor(@ossecAlert, @event)
    @variables = @variableExtractor.run()
    @userExtractor = new UserExtractor(@ossecAlert, @event)
    @users = @userExtractor.run()

  updateEvent: ->
    @event.updateEvent(sourcePort: @attributes.sourcePort)
    @event.updateEvent(sourceIp: @attributes.sourceIp)
    @event.updateEvent(destinationIp: @attributes.destinationIp)
    @event.updateEvent(destinationPort: @attributes.destinationPort)
    @event.updateEvent(fileName: @attributes.fileName)
    @event.updateEvent(newMd5: @attributes.newMd5)
    @event.updateEvent(oldMd5: @attributes.oldMd5)
    @event.updateEvent(newSha1: @attributes.newSha1)
    @event.updateEvent(oldSha1: @attributes.oldSha1)
    @event.updateEvent(severity: @attributes.severity)
    @event.updateEvent(ruleId: @attributes.ruleId)
    @event.updateEvent(description: @attributes.description)
    @event.updateEvent(component: @attributes.component)
    @event.updateEvent(classification: @attributes.classification)
    @event.updateEvent(message: @attributes.message)
    @event.updateEvent(user: @attributes.user)
    @event.updateEvent(device: @attributes.device)
    @event.updateEvent(domains: @variables.domains)
    @event.updateEvent(emails: @variables.emails)
    @event.updateEvent(ipAddrs: @variables.ipAddrs)
    @event.updateEvent(users: @users)
    @event.updateEvent(timestamp: @timeStamp)

module.exports = ProcessOssecAlert




