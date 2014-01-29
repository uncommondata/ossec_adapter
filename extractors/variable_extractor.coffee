class VariableExtractor
  constructor: (@ossec_alert, @event) ->
    @variables = { }

  run: ->
    console.log("Running Variable Extractor...") if debug
    @extractDomains()
    @extractEmails()
    @extractIpAddrs()
    return @variables

  extractIpAddrs: ->
    ipAddrPattern = /(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g
    match = @ossec_alert.message.match ipAddrPattern
    @ipAddrs = (ipAddr for ipAddr in match) if match
    @variables["ipAddrs"] = @ipAddrs
    console.log("IP Addrs: " + @ipAddrs) if debug

  extractDomains: ->
    domainPattern = /([a-z0-9\-]+([\-\.]{1}[a-z0-9\-]+)*\.[a-z]{2,5})/ig
    match = @ossec_alert.message.match domainPattern
    @domains = (domain for domain in match) if match
    @variables["domains"] = @domains
    console.log("Domains: " + @domains) if debug

  extractEmails: ->
    emailPattern = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}/ig
    match = @ossec_alert.message.match emailPattern
    @emails = (email for email in match) if match
    @variables["emails"] = @emails
    console.log("Emails: " + @emails) if debug

module.exports = VariableExtractor