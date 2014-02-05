EventBuilder = require('./event_builder')
OssecAlertAttributesExtractor = require('./extractors/ossec_alert_attributes_extractor')
VariableExtractor = require('./extractors/variable_extractor')
UserExtractor = require('./extractors/user_extractor')
GetMeta = require('./extractors/get_meta')

class ProcessOssecAlert
  constructor: (@ossec_syslog_alert) ->
    console.log("Found OSSEC alert: " + @ossec_syslog_alert) if debug
    @event = new EventBuilder()

  run: ->
    @extractJsonBlock()
    if @ossec_alert?
      @process()
      @updateEvent()
      @uploadEvent()
    else
      console.log("Not an OSSEC alert?: " + @ossec_syslog_alert) if debug

  extractJsonBlock: ->
    ossecJsonPattern = /\bossec:\s(\{\s\"crit\"\:\s\d{1,2}\,\s\"id\"\:\s\d+.*\})/
    match = @ossec_syslog_alert.match ossecJsonPattern
    @ossec_alert = JSON.parse(match[1]) if match

  process: ->
    @attributesExtractor = new OssecAlertAttributesExtractor(@ossec_alert, @event)
    @attributes = @attributesExtractor.run()
    @variableExtractor = new VariableExtractor(@ossec_alert, @event)
    @variables = @variableExtractor.run()
    @userExtractor = new UserExtractor(@ossec_alert, @event)
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

  uploadEvent: ->
    console.log(@event)

module.exports = ProcessOssecAlert




