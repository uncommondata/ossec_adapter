moment = require('moment')

class OssecJsonAlertAttributesExtractor
  constructor: (@timeStamp, @ossecAlert, @event) ->
    @attributes = { }
    @parsingMethods = [ @sourceIp(), @sourcePort(), @destinationIp(), @destinationPort(), @severity(), @ruleId(), @description(),
                        @component(), @classification(), @fileName(), @newMd5(), @oldMd5(), @newSha1(), @oldSha1(), @device(),
                        @message(), @user(), @timestamp() ]

  run: ->
    console.log("Running OSSEC Alert Attributes Extractor...") if debug
    do method for method in @parsingMethods when method isnt undefined
    return @attributes

  timestamp: ->
    @moment = moment(@timeStamp)
    @attributes["timeStamp"] = @moment.utc()
    console.log("Timestamp: " + @moment.utc()) if debug

  device: ->
    @dev = @component.split(/\-\>/)[0] if @component?
    @device = @dev.replace(/\)/g,'').replace(/\(/g,'').replace(/any/g,'').replace(/\s+/g,'')
    @attributes["device"] = @device
    console.log("Device: " + @device) if debug

  sourcePort: ->
    @sourcePort = @ossecAlert.src_port
    @attributes["sourcePort"] = @sourcePort
    console.log("Source Port: " + @sourcePort) if debug

  sourceIp: ->
    @sourceIp = @ossecAlert.src_ip
    @attributes["sourceIp"] = @sourceIp
    console.log("Source Ip: " + @sourceIp) if debug

  destinationIp: ->
    @destinationIp = @ossecAlert.dst_ip
    @attributes["destinationIp"] = @destinationIp
    console.log("Destination Ip: " + @destinationIp) if debug

  destinationPort: ->
    @destinationPort = @ossecAlert.dst_port
    @attributes["destinationPort"] = @destinationPort
    console.log("Destination Port: " + @destinationPort) if debug

  fileName: ->
    @fileName = @ossecAlert.file
    @attributes["fileName"] = @fileName
    console.log("File Name: " + @fileName) if debug

  newMd5: ->
    @newMd5 = @ossecAlert.md5_new
    @attributes["newMd5"] = @newMd5
    console.log("New MD5: " + @newMd5) if debug

  oldMd5: ->
    @oldMd5 = @ossecAlert.md5_old
    @attributes["oldMd5"] = @oldMd5
    console.log("Old MD5: " + @oldMd5) if debug

  newSha1: ->
    @newSha1 = @ossecAlert.sha1_new
    @attributes["newSha1"] = @newSha1
    console.log("New SHA-1: " + @newSha1) if debug

  oldSha1: ->
    @oldSha1 = @ossecAlert.sha1_old
    @attributes["oldSha1"] = @oldSha1
    console.log("Old SHA-1: " + @oldSha1) if debug

  severity: ->
    @severity = @ossecAlert.crit
    @attributes["severity"] = @severity
    console.log("Severity: " + @severity) if debug

  ruleId: ->
    @ruleId = @ossecAlert.id
    @attributes["ruleId"] = @ruleId
    console.log("RuleId: " + @ruleId) if debug

  description: ->
    @description = @ossecAlert.description
    @attributes["description"] = @description
    console.log("Description: " + @description) if debug

  component: ->
    @component = @ossecAlert.component
    @attributes["component"] = @component
    console.log("Component: " + @component) if debug

  classification: ->
    @classification = @ossecAlert.classification
    @attributes["classification"] = @classification
    console.log("Classification: " + @classification) if debug

  message: ->
    @message = @ossecAlert.message
    @attributes["message"] = @message
    console.log("Message: " + @message) if debug

  user: ->
    @user = @ossecAlert.acct
    @attributes["user"] = @user
    console.log("User: " + @user) if debug

module.exports = OssecJsonAlertAttributesExtractor