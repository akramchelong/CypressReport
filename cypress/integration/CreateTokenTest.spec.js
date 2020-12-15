const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const NodeRSA = require('node-rsa')
const qs = require('querystring')
const url = require('url')

describe('Test CreateToken', function () {
  // Runs once before all tests in the block
  beforeEach(function () {
    // Fetch the data from the const.json file
    cy.fixture('const.json').then(function (data) {
      this.readOnly = data
    })

    // Fetch the data from the oauthCred.json file
    cy.fixture('oauthCred.json').then(function (data) {
      this.data = data

      // PKCE
      // Creates a code verifier which consist of 32 bytes
      // This corresponds to 43 characters
      const codeVerifier = cy.helpers.base64URLEncode(crypto.randomBytes(32))
      this.data.codeVerifier = codeVerifier

      // Creates a code challenge based on the code verifier
      const sha256 = cy.helpers.sha256(codeVerifier)
      const codeChallenge = cy.helpers.base64URLEncode(sha256)
      this.data.codeChallenge = codeChallenge

      // Creates a string that contains of 11 alphanumeric characters
      // This will be used as nonce
      const nonce = cy.helpers.generateAlphanumerics(11)
      this.data.nonce = nonce

      // Get the issuer from metadata
      cy.getRequest(this.readOnly.metadata_endpoint).then((response) => {
        this.data.issuer = response.body.issuer
      })

      const item = {
        redirect_uris: ['https://oidcdebugger.com/debug'],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        application_type: 'web',
        client_name: 'AXIS VMS Web Client',
        client_description: 'Axis VMS Web Client version x.x',
        token_endpoint_auth_method: 'client_secret_basic'
      }

      cy.createClientsRequest(this.readOnly.client_endpoint, item).then((response) => {
        this.data.clientId = response.body.client_id
        this.data.clientSecret = response.body.client_secret
        this.data.redirectUris = response.body.redirect_uris
        this.data.responseTypes = response.body.response_types
        this.data.clientName = response.body.client_name
        this.data.clientDescription = response.body.client_description
        this.data.state = 'home'

        // Waits 2 seconds before each test
        // This is due to the rate limit set on all requests refilled per seconds
        // set to 3 and 1 respectively. If a cy.wait() is not added, it will fail the test
        // with a status code: 429 with error message: Error: "rate_limit", description: "Too Many Requests
        cy.wait(2000)

        cy.log('********* beforeEach has been successfully completed *********')
      })
    })
  })

  it('Verify that a token gets created, verified and refreshed', function () {
    const params = {
      client_id: this.data.clientId,
      redirect_uri: this.data.redirectUris[0],
      nonce: this.data.nonce,
      scope: 'openid',
      response_type: this.data.responseTypes,
      code_challenge: this.data.codeChallenge,
      code_challenge_method: 'S256',
      state: this.data.state
    }

    const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

    // Perform initial authentication request
    cy.getRequest(authorizationRequestUrl).then((response) => {
      expect(response.status).to.eq(200)
      const authSessionId = cy.helpers.getSessionId(response.body)

      const authHandleRequestUrl = this.readOnly.authorization_handle_endpoint
      const body = {
        client_id: this.data.clientId,
        redirect_uri: this.data.redirectUris[0],
        auth_session_id: authSessionId,
        username: this.data.userName,
        password: this.data.password
      }

      // Performs POST request which will submit the form-data
      cy.postRequest(authHandleRequestUrl, body).then((response) => {
        const locationUrl = url.parse(response.headers.location, true)
        const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
        const query = locationUrl.query
        expect(response.status).to.eq(302)
        expect(host).eq(this.data.redirectUris[0])
        expect(query.code).to.match(/[a-zA-Z0-9-]+/)
        expect(query.iss).eq(this.data.issuer)
        expect(query.state).eq(this.data.state)

        const tokenRequestUrl = this.readOnly.token_endpoint
        const body = {
          grant_type: 'authorization_code',
          code: query.code,
          redirect_uri: this.data.redirectUris[0],
          code_verifier: this.data.codeVerifier
        }

        // Perform token exchange
        cy.postAuthRequest(tokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
          .then((response) => {
            expect(response.status).to.eq(200)
            const refreshToken = response.body.refresh_token

            // Expects a refresh token with 40 characters
            // This is the minimum requirement set for a refresh token
            expect(response.body.refresh_token).to.have.length(40)
            expect(response.body.access_token).to.not.eq(response.body.id_token)

            // Access token should have an expiration time to 900 seconds
            expect(response.body.expires_in).to.eq(900)

            // Decode the id token from JWT and search in the payload for nonce
            // The nonce used from auth request should be the same as the decoded nonce from JWT
            const accessToken = response.body.access_token
            const idToken = response.body.id_token
            const decoded = jwt.decode(idToken)
            expect(this.data.nonce).eq(decoded.nonce)

            // Get the decoded data from access token
            const decodedAccessToken = jwt.decode(accessToken, {
              complete: true
            })
            // Verify the correct algorithm and token type in headers for access token
            expect(decodedAccessToken.header).to.have.property('alg').eq('RS256')
            expect(decodedAccessToken.header).to.have.property('kid').and.not.be.empty
            expect(decodedAccessToken.header).to.have.property('typ').eq('JWT')

            // Get the decoded data from id token
            const decodedIdToken = jwt.decode(idToken, {
              complete: true
            })

            cy.wait(2000)

            // Verify the correct algorithm and token type in headers for id token
            expect(decodedIdToken.header).to.have.property('alg').eq('RS256')
            expect(decodedIdToken.header).to.have.property('kid').and.not.be.empty
            expect(decodedIdToken.header).to.have.property('typ').eq('JWT')

            // Create public key from components method
            const key = new NodeRSA()

            // Fetch the modulus that gets created when requesting oauth2/keys
            cy.getRequest(this.readOnly.keys_endpoint).then(response => {
              const modulus = Buffer.from(response.body.keys[0].n, 'base64')
              const exponent = Buffer.from(response.body.keys[0].e, 'base64')

              const componentsPublicKey = key.importKey({
                n: modulus,
                e: exponent
              }, 'components-public')

              const publicKey = componentsPublicKey.exportKey('pkcs8-public-pem')

              // Verify access token symmetric - synchronous
              const accessTokenVerified = jwt.verify(accessToken, publicKey)

              expect(accessTokenVerified).to.have.property('userSID').and.not.be.empty
              expect(accessTokenVerified).to.have.property('username').eq(this.data.userName)
              expect(accessTokenVerified).to.have.property('groups').to.exist
              expect(accessTokenVerified).to.have.property('groupsNiceName').eq('Users')
              expect(accessTokenVerified).to.have.property('purpose').eq('access_token')
              expect(accessTokenVerified).to.have.property('aud').deep.eq([this.data.clientId])
              expect(accessTokenVerified).to.have.property('exp').to.exist
              expect(accessTokenVerified).to.have.property('jti').and.not.be.empty
              expect(accessTokenVerified).to.have.property('iat').to.exist
              expect(accessTokenVerified).to.have.property('iss').eq('https://localhost:50120')
              expect(accessTokenVerified).to.have.property('nbf').to.exist
              expect(accessTokenVerified).to.have.property('sub').eq(this.data.userName)

              // Verify id token symmetric - synchronous
              const idTokenVerified = jwt.verify(idToken, publicKey)

              expect(idTokenVerified).to.have.property('username').eq(this.data.userName)
              expect(idTokenVerified).to.have.property('nonce').eq(this.data.nonce)
              expect(idTokenVerified).to.have.property('azp').and.not.be.empty
              expect(idTokenVerified).to.have.property('purpose').eq('id_token')
              expect(idTokenVerified).to.have.property('aud').deep.eq([this.data.clientId])
              expect(idTokenVerified).to.have.property('exp').to.exist
              expect(idTokenVerified).to.have.property('jti').and.not.be.empty
              expect(idTokenVerified).to.have.property('iat').to.exist
              expect(idTokenVerified).to.have.property('iss').eq('https://localhost:50120')
              expect(idTokenVerified).to.have.property('nbf').to.exist
              expect(idTokenVerified).to.have.property('sub').eq(this.data.userName)

              // Refresh token
              const refreshTokenRequestUrl = this.readOnly.token_endpoint
              const body = {
                grant_type: 'refresh_token',
                refresh_token: refreshToken
              }

              cy.wait(2000)

              // Performs a POST request which will refresh the token
              cy.postAuthRequest(refreshTokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
                .then((response) => {
                  expect(response.status).to.eq(200)

                  // Expects a refresh token with 40 characters
                  // This is the minimum requirement set for a refresh token
                  expect(response.body.refresh_token).to.have.length(40)

                  // Access token should have an expiration time to 900 seconds
                  expect(response.body.expires_in).to.eq(900)

                  // Decode the id token from JWT and search in the payload for nonce
                  // The nonce used from auth request should be the same as the decoded nonce from JWT
                  const refreshAccessToken = response.body.access_token
                  const refreshIdToken = response.body.id_token
                  const decoded = jwt.decode(refreshIdToken)
                  expect(this.data.nonce).eq(decoded.nonce)

                  // Get the decoded data from access token
                  const decodedRefreshAccessToken = jwt.decode(refreshAccessToken, {
                    complete: true
                  })

                  // Verify the correct algorithm and token type in headers for the refreshed access- and id token
                  // is the same as the first requested token request
                  expect(decodedRefreshAccessToken.header.alg).eq(decodedAccessToken.header.alg)
                  expect(decodedRefreshAccessToken.header.kid).eq(decodedAccessToken.header.kid)
                  expect(decodedRefreshAccessToken.header.typ).eq(decodedAccessToken.header.typ)

                  // Get the decoded data from id token
                  const decodedRefreshIdToken = jwt.decode(refreshIdToken, {
                    complete: true
                  })

                  expect(decodedRefreshIdToken.header.alg).eq(decodedIdToken.header.alg)
                  expect(decodedRefreshIdToken.header.kid).eq(decodedIdToken.header.kid)
                  expect(decodedRefreshIdToken.header.typ).eq(decodedIdToken.header.typ)

                  cy.wait(2000)

                  // Create public key from components method
                  const publicKey = componentsPublicKey.exportKey('pkcs8-public-pem')

                  // Compare the the data from the refreshed access token with the first verified access token
                  const refreshedAccessToken = jwt.verify(refreshAccessToken, publicKey)

                  expect(refreshedAccessToken.userSID).eq(accessTokenVerified.userSID)
                  expect(refreshedAccessToken.username).eq(accessTokenVerified.username)
                  expect(refreshedAccessToken.groups).eq(accessTokenVerified.groups)
                  expect(refreshedAccessToken.groupsNiceName).eq(accessTokenVerified.groupsNiceName)
                  expect(refreshedAccessToken.purpose).eq(accessTokenVerified.purpose)
                  expect(refreshedAccessToken.aud[0]).eq(accessTokenVerified.aud[0])
                  expect(refreshedAccessToken.exp).not.eq(accessTokenVerified.exp)
                  expect(refreshedAccessToken.jti).not.eq(accessTokenVerified.jti)
                  expect(refreshedAccessToken.iat).not.eq(accessTokenVerified.iat)
                  expect(refreshedAccessToken.iss).eq(accessTokenVerified.iss)
                  expect(refreshedAccessToken.nbf).not.eq(accessTokenVerified.nbf)
                  expect(refreshedAccessToken.sub).eq(accessTokenVerified.sub)

                  // Compare the the data from the refreshed id token with the first verified id token
                  const refreshedIdToken = jwt.verify(refreshIdToken, publicKey)

                  expect(refreshedIdToken.username).eq(idTokenVerified.username)
                  expect(refreshedIdToken.nonce).eq(idTokenVerified.nonce)
                  expect(refreshedIdToken.azp).eq(idTokenVerified.azp)
                  expect(refreshedIdToken.purpose).eq(idTokenVerified.purpose)
                  expect(refreshedIdToken.aud[0]).eq(idTokenVerified.aud[0])
                  expect(refreshedIdToken.exp).not.eq(idTokenVerified.exp)
                  expect(refreshedIdToken.jti).not.eq(idTokenVerified.jti)
                  expect(refreshedIdToken.iat).not.eq(idTokenVerified.iat)
                  expect(refreshedIdToken.iss).eq(idTokenVerified.iss)
                  expect(refreshedIdToken.nbf).not.eq(idTokenVerified.nbf)
                  expect(refreshedIdToken.sub).eq(idTokenVerified.sub)
                })
            })
          })
      })
    })
  })

  it('Verify that code verifier with more than 255 characters returns error', function () {
    // PKCE
    // Creates a code verifier which consist of 195 bytes
    // This corresponds to 260 characters
    const codeVerifier = cy.helpers.base64URLEncode(crypto.randomBytes(195))

    // Creates a code challenge based on the code verifier
    const sha256 = cy.helpers.sha256(codeVerifier)
    const codeChallenge = cy.helpers.base64URLEncode(sha256)

    // code verifier is set to 260 characters which is not valid
    // The maximum length it allows is set to 255 characters
    const params = {
      client_id: this.data.clientId,
      redirect_uri: this.data.redirectUris[0],
      nonce: this.data.nonce,
      scope: 'openid',
      response_type: this.data.responseTypes,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state: this.data.state
    }

    const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

    // Perform initial authentication request
    cy.getRequest(authorizationRequestUrl).then((response) => {
      expect(response.status).to.eq(200)
      const authSessionId = cy.helpers.getSessionId(response.body)

      const authHandleRequestUrl = this.readOnly.authorization_handle_endpoint
      const body = {
        client_id: this.data.clientId,
        redirect_uri: this.data.redirectUris[0],
        auth_session_id: authSessionId,
        username: this.data.userName,
        password: this.data.password
      }

      // Performs POST request which submit the form-data
      cy.postRequest(authHandleRequestUrl, body).then((response) => {
        const locationUrl = url.parse(response.headers.location, true)
        const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
        const query = locationUrl.query
        expect(response.status).to.eq(302)
        expect(host).eq(this.data.redirectUris[0])
        expect(query.code).to.match(/[a-zA-Z0-9-]+/)
        expect(query.iss).eq(this.data.issuer)
        expect(query.state).eq(this.data.state)

        const tokenRequestUrl = this.readOnly.token_endpoint
        const body = {
          grant_type: 'authorization_code',
          code: query.code,
          redirect_uri: this.data.redirectUris[0],
          code_verifier: codeVerifier
        }

        cy.wait(2000)

        // Perform token exchange
        cy.postAuthRequest(tokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
          .then((response) => {
            expect(response.status).eq(400)
            expect(response.body.error).eq('invalid_request')
            expect(response.body.error_description).eq('code_verifier contains too many elements')
          })
      })
    })
  })

  it('Verify that invalid code verifier returns error', function () {
    // Create a random code challenge
    const codeVerifier = cy.helpers.base64URLEncode(crypto.randomBytes(32))
    const sha256 = cy.helpers.sha256(codeVerifier)
    const codeChallenge = cy.helpers.base64URLEncode(sha256)

    const params = {
      client_id: this.data.clientId,
      redirect_uri: this.data.redirectUris[0],
      nonce: this.data.nonce,
      scope: 'openid',
      response_type: this.data.responseTypes,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state: this.data.state
    }

    const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

    // Perform initial authentication request
    cy.getRequest(authorizationRequestUrl).then((response) => {
      expect(response.status).to.eq(200)
      const authSessionId = cy.helpers.getSessionId(response.body)

      const authHandleRequestUrl = this.readOnly.authorization_handle_endpoint
      const body = {
        client_id: this.data.clientId,
        redirect_uri: this.data.redirectUris[0],
        auth_session_id: authSessionId,
        username: this.data.userName,
        password: this.data.password
      }

      // Performs POST request which will submit the form-data
      cy.postRequest(authHandleRequestUrl, body).then((response) => {
        const locationUrl = url.parse(response.headers.location, true)
        const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
        const query = locationUrl.query
        expect(response.status).to.eq(302)
        expect(host).eq(this.data.redirectUris[0])
        expect(query.code).to.match(/[a-zA-Z0-9-]+/)
        expect(query.iss).eq(this.data.issuer)
        expect(query.state).eq(this.data.state)

        const tokenRequestUrl = this.readOnly.token_endpoint
        const body = {
          grant_type: 'authorization_code',
          code: query.code,
          redirect_uri: this.data.redirectUris[0],
          code_verifier: this.data.codeVerifier
        }

        cy.wait(2000)

        // Perform token exchange
        // In this case it will fail since the code verifier is
        // not connected to the code challenge
        cy.postAuthRequest(tokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
          .then((response) => {
            expect(response.status).eq(400)
            expect(response.body.error).eq('invalid_grant')
            expect(response.body.error_description).eq('Invalid code_verifier')
          })
      })
    })
  })
})
