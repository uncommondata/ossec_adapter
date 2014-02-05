// Generated by CoffeeScript 1.6.3
(function() {
  var EventBuilder, GetMeta, OssecAlertAttributesExtractor, ProcessOssecAlert, UserExtractor, VariableExtractor;

  EventBuilder = require('./event_builder');

  OssecAlertAttributesExtractor = require('./extractors/ossec_alert_attributes_extractor');

  VariableExtractor = require('./extractors/variable_extractor');

  UserExtractor = require('./extractors/user_extractor');

  GetMeta = require('./extractors/get_meta');

  ProcessOssecAlert = (function() {
    function ProcessOssecAlert(ossec_syslog_alert) {
      this.ossec_syslog_alert = ossec_syslog_alert;
      if (debug) {
        console.log("Found OSSEC alert: " + this.ossec_syslog_alert);
      }
      this.event = new EventBuilder();
    }

    ProcessOssecAlert.prototype.run = function() {
      this.extractJsonBlock();
      if (this.ossec_alert != null) {
        this.process();
        this.updateEvent();
        return this.uploadEvent();
      } else {
        if (debug) {
          return console.log("Not an OSSEC alert?: " + this.ossec_syslog_alert);
        }
      }
    };

    ProcessOssecAlert.prototype.extractJsonBlock = function() {
      var match, ossecJsonPattern;
      ossecJsonPattern = /\bossec:\s(\{\s\"crit\"\:\s\d{1,2}\,\s\"id\"\:\s\d+.*\})/;
      match = this.ossec_syslog_alert.match(ossecJsonPattern);
      if (match) {
        return this.ossec_alert = JSON.parse(match[1]);
      }
    };

    ProcessOssecAlert.prototype.process = function() {
      this.attributesExtractor = new OssecAlertAttributesExtractor(this.ossec_alert, this.event);
      this.attributes = this.attributesExtractor.run();
      this.variableExtractor = new VariableExtractor(this.ossec_alert, this.event);
      this.variables = this.variableExtractor.run();
      this.userExtractor = new UserExtractor(this.ossec_alert, this.event);
      return this.users = this.userExtractor.run();
    };

    ProcessOssecAlert.prototype.updateEvent = function() {
      this.event.updateEvent({
        sourcePort: this.attributes.sourcePort
      });
      this.event.updateEvent({
        sourceIp: this.attributes.sourceIp
      });
      this.event.updateEvent({
        destinationIp: this.attributes.destinationIp
      });
      this.event.updateEvent({
        destinationPort: this.attributes.destinationPort
      });
      this.event.updateEvent({
        fileName: this.attributes.fileName
      });
      this.event.updateEvent({
        newMd5: this.attributes.newMd5
      });
      this.event.updateEvent({
        oldMd5: this.attributes.oldMd5
      });
      this.event.updateEvent({
        newSha1: this.attributes.newSha1
      });
      this.event.updateEvent({
        oldSha1: this.attributes.oldSha1
      });
      this.event.updateEvent({
        severity: this.attributes.severity
      });
      this.event.updateEvent({
        ruleId: this.attributes.ruleId
      });
      this.event.updateEvent({
        description: this.attributes.description
      });
      this.event.updateEvent({
        component: this.attributes.component
      });
      this.event.updateEvent({
        classification: this.attributes.classification
      });
      this.event.updateEvent({
        message: this.attributes.message
      });
      this.event.updateEvent({
        user: this.attributes.user
      });
      this.event.updateEvent({
        device: this.attributes.device
      });
      this.event.updateEvent({
        domains: this.variables.domains
      });
      this.event.updateEvent({
        emails: this.variables.emails
      });
      this.event.updateEvent({
        ipAddrs: this.variables.ipAddrs
      });
      return this.event.updateEvent({
        users: this.users
      });
    };

    ProcessOssecAlert.prototype.uploadEvent = function() {
      return console.log(this.event);
    };

    return ProcessOssecAlert;

  })();

  module.exports = ProcessOssecAlert;

}).call(this);

/*
//@ sourceMappingURL=process_ossec_alert.map
*/
