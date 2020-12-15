const crypto = require('crypto')

cy.helpers = {
  repeatString: (str, num) => {
    let builder = ''
    for (let i = 0; i < num; i++) {
      builder += str
    }
    return builder
  },
  generateAlphanumerics: (num) => {
    let builder = ''
    const possible = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

    for (let i = 0; i < num; i++) {
      builder += possible.charAt(Math.floor(Math.random() * possible.length))
    }
    return builder
  },
  base64URLEncode: (str) => {
    return str.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '')
  },
  sha256: (buffer) => {
    return crypto.createHash('sha256').update(buffer).digest()
  },
  getSessionId: (body) => {
    const authSessionIdRegexp = /auth_session_id" value="([a-zA-Z0-9-]+)">/
    const res = authSessionIdRegexp.exec(body)

    return res[1]
  },
  getAuthCode: (headers) => {
    const authCodeRegexp = /\?code=([a-zA-Z0-9-]+)/
    const res = authCodeRegexp.exec(headers.location)

    return res[1]
  }
}
