class OssecAlertAttributesExtractor
  constructor: (@ossec_alert, @event) ->
    @attributes = { }
    @parsing_methods = [ @sourceIp(), @sourcePort(), @destinationIp(), @destinationPort(), @severity(), @ruleId(), @description(),
                         @component(), @classification(), @fileName(), @newMd5(), @oldMd5(), @newSha1(), @oldSha1(), @device(),
                         @message(), @user() ]

  run: ->
    console.log("Running OSSEC Alert Attributes Extractor...") if debug
    do method for method in @parsing_methods when method isnt undefined
    return @attributes

  device: ->
    @dev = @component.split(/\-\>/)[0] if @component?
    @device = @dev.replace(/\)/g,'').replace(/\(/g,'').replace(/any/g,'').replace(/\s+/g,'')
    @attributes["device"] = @device
    console.log("Device: " + @device) if debug

  sourcePort: ->
    @sourcePort = @ossec_alert.src_port
    @attributes["sourcePort"] = @sourcePort
    console.log("Source Port: " + @sourcePort) if debug

  sourceIp: ->
    @sourceIp = @ossec_alert.src_ip
    @attributes["sourceIp"] = @sourceIp
    console.log("Source Ip: " + @sourceIp) if debug

  destinationIp: ->
    @destinationIp = @ossec_alert.dst_ip
    @attributes["destinationIp"] = @destinationIp
    console.log("Destination Ip: " + @destinationIp) if debug

  destinationPort: ->
    @destinationPort = @ossec_alert.dst_port
    @attributes["destinationPort"] = @destinationPort
    console.log("Destination Port: " + @destinationPort) if debug

  fileName: ->
    @fileName = @ossec_alert.file
    @attributes["fileName"] = @fileName
    console.log("File Name: " + @fileName) if debug

  newMd5: ->
    @newMd5 = @ossec_alert.md5_new
    @attributes["newMd5"] = @newMd5
    console.log("New MD5: " + @newMd5) if debug

  oldMd5: ->
    @oldMd5 = @ossec_alert.md5_old
    @attributes["oldMd5"] = @oldMd5
    console.log("Old MD5: " + @oldMd5) if debug

  newSha1: ->
    @newSha1 = @ossec_alert.sha1_new
    @attributes["newSha1"] = @newSha1
    console.log("New SHA-1: " + @newSha1) if debug

  oldSha1: ->
    @oldSha1 = @ossec_alert.sha1_old
    @attributes["oldSha1"] = @oldSha1
    console.log("Old SHA-1: " + @oldSha1) if debug

  severity: ->
    @severity = @ossec_alert.crit
    @attributes["severity"] = @severity
    console.log("Severity: " + @severity) if debug

  ruleId: ->
    @ruleId = @ossec_alert.id
    @attributes["ruleId"] = @ruleId
    console.log("RuleId: " + @ruleId) if debug

  description: ->
    @description = @ossec_alert.description
    @attributes["description"] = @description
    console.log("Description: " + @description) if debug

  component: ->
    @component = @ossec_alert.component
    @attributes["component"] = @component
    console.log("Component: " + @component) if debug

  classification: ->
    @classification = @ossec_alert.classification
    @attributes["classification"] = @classification
    console.log("Classification: " + @classification) if debug

  message: ->
    @message = @ossec_alert.message
    @attributes["message"] = @message
    console.log("Message: " + @message) if debug

  user: ->
    @user = @ossec_alert.acct
    @attributes["user"] = @user
    console.log("User: " + @user) if debug

module.exports = OssecAlertAttributesExtractor