EventBuilder = require('./event_builder')
VariableExtractor = require('./extractors/variable_extractor')
UserExtractor = require('./extractors/user_extractor')
GetMeta = require('./extractors/get_meta')

class ProcessOssecAlertLog
  constructor: (@ossecAlertLog) ->
    ALERT_DEVICE_PATTERN = ///^\d{4}\s\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\(?(([A-Za-z0-9_\-]+\.?){6,}?)///
    ALERT_SRCIP_PATTERN = ///^Src\sIP:\s(.*)///
    ALERT_USER_PATTERN = ///^User:\s(.*)///
    ALERT_DATETIME_GROUP_PATTERN = ///^\*\*\sAlert\s(\d+)\.\d+:.*\s-\s(.*)///
    ALERT_RULEID_LEVEL_COMMENT_PATTERN = ///^Rule:\s(\d+)\s+\(level\s(\d+)\)\s->\s(.*)///
    console.log("Found OSSEC alert log: " + @ossecAlertLog) if debug
    @event = new EventBuilder()

module.exports = ProcessOssecAlertLog




