class UserExtractor

  USERNAME_PATTERNS = [
    /\bUser\sname:\s*([A-Za-z0-9_-]+)\b/i,
    /\br?user[\s\=]([A-Za-z0-9_-]\\[A-Za-z0-9_-])\b/i,
    /\br?user\s?[\s\=]\s?([A-Za-z0-9_-]+)\b/i,
    /\buser\s\[([A-Za-z0-9_-]+)\]\b/i,
    /\buser\s\'([A-Za-z0-9_-]+)\'@\'/i,
    /\buser\s\"([A-Za-z0-9_-]+)\"/i,
    /\bfailed login \w+ from \(\w+\) for ([A-Za-z0-9_-]+)\b/i,
    /\bfailed login for ([A-Za-z0-9_-]+)\b/,
    /\bpassword for ([A-Za-z0-9_-]+)/i,
    /\bauth\=([A-Za-z0-9_-]+)/i,
    /\bfailed\sfor\s([A-Za-z0-9_-]+)\b/i,
    /\bsu\:\s([A-Za-z0-9_-]+)\sto\sroot\b/i,
    /\bchanging\sfrom\s([A-Za-z0-9_-]+)\sto\sroot\b/i,
    /\blogin\s([A-Za-z0-9_-]+)\b/i,
    /\bThe\slogon\sto\saccount:\s([A-Za-z0-9_-]+)\b/i,
    /\bconsole\sby\s([A-Za-z0-9_-]+)\b/i,
    /new\suser:\sname\=([A-Za-z0-9_-]+)/i,
    /\/su -? ([A-Za-z0-9_-]+)/i
    /\bAccepted\spublickey\sfor\s([A-Za-z0-9_-]+)\b/i
  ]

  BAD_USERNAMES = [ 'rhost', 'unknown', 'does', 'not', 'invalid', 'uid', 'from', 'refused', 'login',
                    'for', '1', '2', '3', 'protocol', 'tcp', 'udp', 'requested', 'name' ]

  constructor: (@ossec_alert, @event) ->
    @users = []

  run: ->
    console.log("Running User Extractor...") if debug
    @extractUsers()
    return @users

  extractUsers: ->
    for pattern in USERNAME_PATTERNS
      match = @ossec_alert.message.match pattern
      if match
        detectedUsers = (user for user in match[1...] when user not in BAD_USERNAMES)
        @users = detectedUsers.map (user) -> { identifier: user, username: user }
        Array::push.apply @users

    console.log("Users: " + @users) if debug

module.exports = UserExtractor
