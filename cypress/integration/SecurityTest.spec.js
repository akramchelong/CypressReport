const crypto = require('crypto')
const qs = require('querystring')
const url = require('url')

describe('Oauth Security Testing', function () {
  // Runs once before all tests in the block
  beforeEach(function () {
    cy.wait(2000)

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

      // Performs a POST request and stores the client id
      const item = {
        redirect_uris: ['https://oidcdebugger.com/debug', 'https://axis.com'],
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
      })
      cy.createClientsRequest(this.readOnly.client_endpoint, item).then((response) => {
        this.data.clientId1 = response.body.client_id
        this.data.clientSecret1 = response.body.client_secret

        // Waits 2 seconds before each test. This is due to the rate limit set
        // on all requests refilled per seconds set to 3 and 1 respectively. If
        // a wait is not added, it will fail the test with a status code: 429
        // with error message: Error: "rate_limit", description: "Too Many
        // Requests
        cy.wait(2000)
        cy.log('********* beforeEach has been successfully completed *********')
      })
    })
  })

  /*
     * [#1.x] Tokens (auth codes, access token, refresh token)
     *
     * Validations that verify a specific countermeasure that prevents an attacker from stealing tokens.
     * E.g. Verify that authorization code is bound to client id.
     */
  describe('[#1] Tokens', function () {
    it('[#1.1] Verify authorization code is bound to client', function () {
      // https://tools.ietf.org/html/rfc6819#section-5.2.4.4

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
          expect(response.status).to.eq(302)
          expect(response.headers.location).to.include('code=')

          const authCode = cy.helpers.getAuthCode(response.headers)
          const tokenRequestUrl = this.readOnly.token_endpoint
          const body = {
            grant_type: 'authorization_code',
            code: authCode,
            redirect_uri: this.data.redirectUris[0],
            code_verifier: this.data.codeVerifier
          }

          cy.wait(2000)

          // Performs a POST request with another client_id created
          // from client registration. Should not pass through since
          // the authorization code is bound to the client id
          cy.postAuthRequest(tokenRequestUrl, this.data.clientId1, this.data.clientSecret, body)
            .then((response) => {
              expect(response.status).to.eq(401)
              expect(response.body.error).eq('invalid_client')
            })
        })
      })
    })

    it('[#1.2] Verify authorization code is bound to redirect URI', function () {
      // https://tools.ietf.org/html/rfc6819#section-5.2.4.5

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
          expect(response.status).to.eq(302)
          expect(response.headers.location).to.include('code=')

          const authCode = cy.helpers.getAuthCode(response.headers)

          // Instead of the registered redirect uri to the client: https://oidcdebugger.com/debug,
          // we will instead use an unregistred redirect uri: https://oauthdebugger.com/
          // to verify the authorization code is bound to the registered redirect uri
          const tokenRequestUrl = this.readOnly.token_endpoint
          const body = {
            grant_type: 'authorization_code',
            code: authCode,
            redirect_uri: 'https://oauthdebugger.com/',
            code_verifier: this.data.codeVerifier
          }

          cy.wait(2000)

          // Perform token exchange but the url contains an
          // redirect uri that is not registered on the client
          cy.postAuthRequest(tokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
            .then((response) => {
              expect(response.status).to.eq(400)
              expect(response.body.error_description).eq('Redirect URI is not registered on the client')
            })
        })
      })
    })

    it('[#1.3] Verify redirect URI used at token exchange is also used in the initial authorization request', function () {
      // https://tools.ietf.org/html/rfc6749#section-10.6

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

      cy.wait(2000)

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

        cy.wait(2000)

        // Performs POST request which will submit the form-data
        cy.postRequest(authHandleRequestUrl, body).then((response) => {
          expect(response.status).to.eq(302)
          expect(response.headers.location).to.include('code=')

          const authCode = cy.helpers.getAuthCode(response.headers)

          // The redirect_uri inserted to this URL is a registered
          // when creating the client_id, but it was not used for
          // getting the login page of the authorization server
          // Performs a POST request which creates a token
          const tokenRequestUrl = this.readOnly.token_endpoint
          const body = {
            grant_type: 'authorization_code',
            code: authCode,
            redirect_uri: 'https://axis.com',
            code_verifier: this.data.codeVerifier
          }

          cy.wait(2000)

          // Perform token exchange. In this case it will fail since the
          // redirect_uri was not used for the authorization request
          cy.postAuthRequest(tokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
            .then((response) => {
              expect(response.status).eq(400)
              expect(response.body.error).eq('invalid_grant')
              expect(response.body.error_description).eq('Redirect URI was not used for the authorization request')
            })
        })
      })
    })

    it('[#1.4] Verify refresh token is bound to client ID', function () {
      // https://tools.ietf.org/html/rfc6819#section-5.2.2.2

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

      cy.wait(2000)

      // Perform initial authentication request
      cy.getRequest(authorizationRequestUrl).then((response) => {
        expect(response.status).to.eq(200)

        const authSessionId = cy.helpers.getSessionId(response.body)
        const body = {
          client_id: this.data.clientId,
          redirect_uri: this.data.redirectUris[0],
          auth_session_id: authSessionId,
          username: this.data.userName,
          password: this.data.password
        }

        // Performs POST request which will submit the form-data
        cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then((response) => {
          expect(response.status).to.eq(302)
          expect(response.headers.location).to.include('code=')

          const authCode = cy.helpers.getAuthCode(response.headers)

          const body = {
            grant_type: 'authorization_code',
            code: authCode,
            redirect_uri: this.data.redirectUris[0],
            code_verifier: this.data.codeVerifier
          }

          cy.wait(2000)

          // Perform token exchange
          cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body)
            .then((response) => {
              expect(response.status).eq(200)

              const body = {
                grant_type: 'refresh_token',
                refresh_token: response.body.refresh_token
              }

              cy.wait(2000)

              // Refresh access token but now with another client
              cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId1, this.data.clientSecret1, body)
                .then(response => {
                  expect(response.status).to.eq(400)
                  expect(response.body.error).to.eq('invalid_grant')
                  expect(response.body.error_description).to.eq('Refresh token is invalid or has expired')
                })
            })
        })
      })
    })

    it('[#1.5] Verify redirect URI requires HTTPS', function () {
      // https://tools.ietf.org/html/rfc6819#section-4.4.1.5

      const body = {
        redirect_uris: ['https://oidcdebugger.com/debug', 'http://axis.com'],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        application_type: 'web',
        client_name: 'AXIS VMS Web Client',
        client_description: 'Axis VMS Web Client version x.x',
        token_endpoint_auth_method: 'client_secret_basic'
      }

      cy.createClientsRequest(this.readOnly.client_endpoint, body).then((response) => {
        expect(response.status).eq(400)
        expect(response.body.error).eq('invalid_client_metadata')
        expect(response.body.error_description).eq('redirect_uris[1] is not valid')
      })

      const params = {
        client_id: this.data.clientId,
        redirect_uri: 'http://oidcdebugger.com/debug',
        nonce: this.data.nonce,
        scope: 'openid',
        response_type: this.data.responseTypes,
        code_challenge: this.data.codeChallenge,
        code_challenge_method: 'S256',
        state: this.data.state
      }
      const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

      // Verify that authorization request can't be made with an http
      // redirect uri, even though client registered redirect URI with https
      cy.getRequest(authorizationRequestUrl).then((response) => {
        expect(response.status).eq(400)
        expect(response.body).eq('redirect_uri is not registered on the client\n')
      })
    })

    it('[#1.6] Verify that refresh tokens gets rotated', function () {
      // https://tools.ietf.org/html/rfc6819#section-5.2.2.3

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

      cy.wait(2000)

      // Perform initial authentication request
      cy.getRequest(authorizationRequestUrl).then((response) => {
        expect(response.status).to.eq(200)
        const authSessionId = cy.helpers.getSessionId(response.body)

        const body = {
          client_id: this.data.clientId,
          redirect_uri: this.data.redirectUris[0],
          auth_session_id: authSessionId,
          username: this.data.userName,
          password: this.data.password
        }

        cy.wait(2000)

        // Performs POST request which will submit the form-data
        cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then((response) => {
          expect(response.status).to.eq(302)
          expect(response.headers.location).to.include('code=')

          const authCode = cy.helpers.getAuthCode(response.headers)
          const body = {
            grant_type: 'authorization_code',
            code: authCode,
            redirect_uri: this.data.redirectUris[0],
            code_verifier: this.data.codeVerifier
          }

          // Perform token exchange
          cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body)
            .then((response) => {
              expect(response.status).to.eq(200)

              // Refresh token
              const refreshToken = response.body.refresh_token

              const body = {
                grant_type: 'refresh_token',
                refresh_token: refreshToken
              }

              // Perform a refresh token request
              cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body)
                .then((response) => {
                  expect(response.status).to.eq(200)
                  // Compare the new refresh token with the previous one
                  expect(response.body.refresh_token).not.eq(refreshToken)

                  // Perform another refresh token request with the same refresh token.
                  // You should not be able to use the same refresh token more than once
                  // and this should therefore fail.
                  cy.wait(2000)
                  cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body)
                    .then((response) => {
                      expect(response.status).eq(400)
                      expect(response.body.error).to.eq('invalid_grant')
                      expect(response.body.error_description).to.eq('Refresh token is invalid or has expired')
                    })
                })
            })
        })
      })
    })

    it('[#1.7] Verify that a code verifier which is not connected to a code challenge returns error', function () {
      // https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16#section-4.5

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

      cy.wait(2000)

      // Perform initial authentication request
      cy.getRequest(authorizationRequestUrl).then((response) => {
        expect(response.status).to.eq(200)
        const authSessionId = cy.helpers.getSessionId(response.body)

        const body = {
          client_id: this.data.clientId,
          redirect_uri: this.data.redirectUris[0],
          auth_session_id: authSessionId,
          username: this.data.userName,
          password: this.data.password
        }

        // Performs POST request which will submit the form-data
        cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then((response) => {
          expect(response.status).to.eq(302)
          expect(response.headers.location).to.include('code=')
          const authCode = cy.helpers.getAuthCode(response.headers)

          // PKCE
          // Creates a code verifier which consist of 32 bytes
          // This corresponds to 43 characters
          const codeVerifier = cy.helpers.base64URLEncode(crypto.randomBytes(32))

          // The code verifier is not connected to the code challenge
          // used in the previous authorization request
          const body = {
            grant_type: 'authorization_code',
            code: authCode,
            redirect_uri: this.data.redirectUris[0],
            code_verifier: codeVerifier
          }

          // Perform token exchange, but in this case it will
          // fail since the code verifier is invalid.
          cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body)
            .then((response) => {
              expect(response.status).to.eq(400)
              expect(response.body.error).to.eq('invalid_grant')
              expect(response.body.error_description).to.eq('Invalid code_verifier')
            })
        })
      })
    })

    it('[#1.8] Verify correct Referer header policy is used', function () {
      // https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16#section-4.2.4

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

      cy.wait(2000)

      // Perform initial authentication request
      cy.getRequest(authorizationRequestUrl).then(response => {
        expect(response.status).eq(200)
        expect(response.headers['referrer-policy']).eq('no-referrer')
        const authSessionId = cy.helpers.getSessionId(response.body)

        const body = {
          client_id: this.data.clientId,
          redirect_uri: this.data.redirectUris[0],
          auth_session_id: authSessionId,
          username: this.data.userName,
          password: this.data.password
        }

        // Performs POST request which will submit the form-data
        cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then(response => {
          expect(response.status).eq(302)
          expect(response.headers.location).to.include('code=')
          expect(response.headers['referrer-policy']).eq('no-referrer')

          const authCode = cy.helpers.getAuthCode(response.headers)

          const body = {
            grant_type: 'authorization_code',
            code: authCode,
            redirect_uri: this.data.redirectUris[0],
            code_verifier: this.data.codeVerifier
          }

          cy.wait(2000)

          // Perform token exchange
          cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body).then(response => {
            expect(response.status).eq(200)
            expect(response.headers['referrer-policy']).eq('no-referrer')

            const body = {
              grant_type: 'refresh_token',
              refresh_token: response.body.refresh_token
            }

            cy.wait(2000)

            // Performs a POST request for token refresh
            cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body).then(response => {
              expect(response.status).eq(200)
              expect(response.headers['referrer-policy']).eq('no-referrer')
            })
          })
        })
      })

      // Check so that an invalid request contains the referrer policy header
      cy.getRequest(authorizationRequestUrl).then(response => {
        expect(response.status).eq(200)
        const authSessionId = cy.helpers.getSessionId(response.body)

        const body = {
          client_id: this.data.clientId,
          redirect_uri: this.data.redirectUris[0],
          // Add suffix so that session id is invalid
          auth_session_id: authSessionId + 'foobar',
          username: this.data.userName,
          password: this.data.password
        }

        cy.wait(2000)

        // Performs POST request which will submit the form-data
        cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then(response => {
          expect(response.status).eq(302)
          expect(response.headers['referrer-policy']).eq('no-referrer')
          expect(response.headers.location).to.include('error=')
        })
      })
    })

    it('[#1.9] Verify authorization code can only be used once', function () {
      // https://tools.ietf.org/html/rfc6819#section-5.1.5.4

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

        cy.wait(2000)

        // Performs POST request which will submit the form-data
        cy.postRequest(authHandleRequestUrl, body).then((response) => {
          expect(response.status).to.eq(302)
          expect(response.headers.location).to.include('code=')

          const authCode = cy.helpers.getAuthCode(response.headers)
          const tokenRequestUrl = this.readOnly.token_endpoint
          const body = {
            grant_type: 'authorization_code',
            code: authCode,
            redirect_uri: this.data.redirectUris[0],
            code_verifier: this.data.codeVerifier
          }

          cy.wait(2000)

          // Perform code exchange
          cy.postAuthRequest(tokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
            .then(response => {
              expect(response.status).to.eq(200)
              expect(response.body.access_token).not.to.be.empty
            })

          // Perform second code exchange, which should fail
          cy.postAuthRequest(tokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
            .then(response => {
              expect(response.status).to.eq(400)
              expect(response.body.error).eq('invalid_grant')
              expect(response.body.error_description).eq('Code is invalid or has expired')
            })
        })
      })
    })

    it('[#1.10] Verify refresh token gets revoked if an old refresh token gets reused', function () {
      // https://tools.ietf.org/html/rfc6819#section-5.2.2.4

      const body = {
        client_id: this.data.clientId,
        redirect_uri: this.data.redirectUris[0],
        nonce: this.data.nonce,
        scope: 'openid',
        response_type: this.data.responseTypes,
        code_challenge: this.data.codeChallenge,
        code_challenge_method: 'S256',
        state: this.data.state
      }

      const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(body)

      // Perform initial authentication request
      cy.getRequest(authorizationRequestUrl).then((response) => {
        expect(response.status).to.eq(200)
        const authSessionId = cy.helpers.getSessionId(response.body)

        const body = {
          client_id: this.data.clientId,
          redirect_uri: this.data.redirectUris[0],
          auth_session_id: authSessionId,
          username: this.data.userName,
          password: this.data.password
        }

        cy.wait(2000)

        // Performs POST request which will submit the form-data
        cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then((response) => {
          const locationUrl = url.parse(response.headers.location, true)
          const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
          const query = locationUrl.query
          expect(host).eq(this.data.redirectUris[0])

          const body = {
            grant_type: 'authorization_code',
            code: query.code,
            redirect_uri: this.data.redirectUris[0],
            code_verifier: this.data.codeVerifier
          }

          // Perform code exchange
          cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body)
            .then((response) => {
              expect(response.status).to.eq(200)

              // Refresh token
              // Store the refresh token
              const refreshToken = response.body.refresh_token

              const body = {
                grant_type: 'refresh_token',
                refresh_token: refreshToken
              }

              cy.wait(2000)

              // Performs a POST request which will refresh the token
              cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body)
                .then((response) => {
                  expect(response.status).to.eq(200)
                  // Store another refresh token
                  const refreshToken1 = response.body.refresh_token

                  cy.wait(2000)

                  // Use the first stored refresh token again
                  // Performs a POST request which will refresh the token but will fail
                  cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body)
                    .then((response) => {
                      expect(response.status).to.eq(400)
                      expect(response.body.error).to.eq('invalid_grant')
                      expect(response.body.error_description).to.eq('Refresh token is invalid or has expired')

                      // Use the newest refresh token which was stored on the second
                      // attempt of refreshing the token
                      const body = {
                        grant_type: 'refresh_token',
                        refresh_token: refreshToken1
                      }

                      // Performs a POST request which will refresh the token but will fail
                      cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body)
                        .then((response) => {
                          expect(response.status).to.eq(400)
                          expect(response.body.error).to.eq('invalid_grant')
                          expect(response.body.error_description).to.eq('Refresh token is invalid or has expired')
                        })
                    })
                })
            })
        })
      })
    })

    it('[#1.11] Verify correct cache-control and pragma is used', function () {
      // https://tools.ietf.org/html/rfc2616#section-14.9

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

      cy.wait(2000)

      // Perform initial authentication request
      cy.getRequest(authorizationRequestUrl).then(response => {
        expect(response.status).eq(200)
        const authSessionId = cy.helpers.getSessionId(response.body)
        expect(response.headers, 'response headers').to.include({
          'cache-control': 'no-store',
          pragma: 'no-cache'
        })

        const body = {
          client_id: this.data.clientId,
          redirect_uri: this.data.redirectUris[0],
          auth_session_id: authSessionId,
          username: this.data.userName,
          password: this.data.password
        }

        // Performs POST request which will submit the form-data
        cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then(response => {
          expect(response.status).eq(302)
          expect(response.headers.location).to.include('code=')
          expect(response.headers, 'response headers').to.include({
            'cache-control': 'no-store',
            pragma: 'no-cache'
          })

          const authCode = cy.helpers.getAuthCode(response.headers)

          const body = {
            grant_type: 'authorization_code',
            code: authCode,
            redirect_uri: this.data.redirectUris[0],
            code_verifier: this.data.codeVerifier
          }

          cy.wait(2000)

          // Perform code exchange
          cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body).then(response => {
            expect(response.status).eq(200)
            expect(response.headers, 'response headers').to.include({
              'cache-control': 'no-store',
              pragma: 'no-cache'
            })

            const body = {
              grant_type: 'refresh_token',
              refresh_token: response.body.refresh_token
            }

            cy.wait(2000)

            // Performs a POST request for token refresh
            cy.postAuthRequest(this.readOnly.token_endpoint, this.data.clientId, this.data.clientSecret, body).then(response => {
              expect(response.status).eq(200)
              expect(response.headers, 'response headers').to.include({
                'cache-control': 'no-store',
                pragma: 'no-cache'
              })
            })
          })
        })
      })

      // Check so that an invalid request contains the cache-control and pragma header
      cy.getRequest(authorizationRequestUrl).then(response => {
        expect(response.status).eq(200)
        const authSessionId = cy.helpers.getSessionId(response.body)

        const body = {
          client_id: this.data.clientId,
          redirect_uri: this.data.redirectUris[0],
          // Add suffix so that session id is invalid
          auth_session_id: authSessionId + 'foobar',
          username: this.data.userName,
          password: this.data.password
        }

        cy.wait(2000)

        // Performs POST request which will submit the form-data
        cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then(response => {
          expect(response.status).eq(302)
          expect(response.headers, 'response headers').to.include({
            'cache-control': 'no-store',
            pragma: 'no-cache'
          })
          expect(response.headers.location).to.include('error=')
        })
      })
    })
  })

  /*
     * [#2.x] Client Authentication & Authorization
     *
     * Validations that verify a specific countermeasure that prevents an
     * attacker from stealing client credentials (client_id and client_secret).
     * E.g. Verify that each client gets a unique client secret.
     */
  describe('[#2] Client authentication', function () {
    it('[#2.1] Verify client secret length', function () {
      // https://tools.ietf.org/html/rfc6819#section-5.1.4.2.2

      const body = {
        redirect_uris: ['https://oidcdebugger.com/debug', 'https://axis.com'],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        application_type: 'web',
        client_name: 'AXIS VMS Web Client',
        client_description: 'Axis VMS Web Client version x.x',
        token_endpoint_auth_method: 'client_secret_basic'
      }

      cy.createClientsRequest(this.readOnly.client_endpoint, body).then(response => {
        expect(response.status).to.eq(201)
        // Naive test (entropy is not tested). Merely that a secret larger
        // than 30 at least is considered to be "somewhat secure".
        expect(response.body.client_secret.length).to.be.greaterThan(30)
      })
    })

    it('[#2.2] Verify that authorization request without code_challenge returns error', function () {
      // https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16#section-4.8

      // The authorization request are missing the code_challenge
      const params = {
        client_id: this.data.clientId,
        redirect_uri: this.data.redirectUris[0],
        nonce: this.data.nonce,
        scope: 'openid',
        response_type: this.data.responseTypes,
        code_challenge_method: 'S256',
        state: this.data.state
      }
      const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

      cy.wait(2000)
      cy.getRequest(authorizationRequestUrl).then((response) => {
        expect(response.status).to.eq(302)
        expect(response.headers.location).to.include('error=')
      })
    })

    it('[#2.3] Verify that client secret and client id can not be used instead of basic auth', function () {
      // https://tools.ietf.org/html/rfc6819#section-4.6.6

      // Check the metadata and search for token_endpoint_auth_methods_supported
      // and verify that the only value in that array is client_secret_basic.
      cy.request('GET', this.readOnly.endpoint + '/.well-known/openid-configuration')
        .then((response) => {
          expect(response.body.token_endpoint_auth_methods_supported).deep.eq(['client_secret_basic'])
        })

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

      cy.wait(2000)

      // Perform initial authentication request
      cy.getRequest(authorizationRequestUrl).then((response) => {
        expect(response.status).to.eq(200)
        const authSessionId = cy.helpers.getSessionId(response.body)

        const body = {
          client_id: this.data.clientId,
          redirect_uri: this.data.redirectUris[0],
          auth_session_id: authSessionId,
          username: this.data.userName,
          password: this.data.password
        }

        cy.wait(2000)

        // Performs POST request which will submit the form-data
        cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then((response) => {
          expect(response.status).to.eq(302)
          expect(response.headers.location).to.include('code=')
          const authCode = cy.helpers.getAuthCode(response.headers)

          const body = {
            grant_type: 'authorization_code',
            code: authCode,
            redirect_uri: this.data.redirectUris[0],
            code_verifier: this.data.codeVerifier,
            client_id: this.data.clientId,
            client_secret: this.data.clientSecret
          }

          // Performs a POST request which is not using basic auth
          // with client id as username and client secret as
          // password. Instead we add the these data in the body for
          // this token request.
          cy.postRequest(this.readOnly.token_endpoint, body).then((response) => {
            expect(response.status).eq(401)
            expect(response.body.error).eq('invalid_client')
            expect(response.body.error_description).eq('Missing or invalid authorization header')
          })
        })
      })
    })
  })

  /*
     * [#3.x] End User Authentication
     *
     * Validations that verify a specific countermeasure that prevents an
     * attacker from stealing user credentials (username & user password).
     * E.g. Verify that redirect_uri is bound to the client_id, vulnerabilities
     * that can be used to create a phishing attack, etc.
     */
  describe('[#3] End user authentication', function () {
    it('[#3.1] Verify redirect URI that contains wildcard fails to register a client', function () {
      // https://tools.ietf.org/html/rfc6819#section-4.1.5

      // redirect_uris includes URL links that contains wildards.
      // This is not supported and should fail to register the client.
      const body = {
        redirect_uris: ['https://oidcdebugger.com/debug', 'https://*.oidcdebugger.com/debug', 'https://axis.com', 'https://*.axis.com'],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        application_type: 'web',
        client_name: 'AXIS VMS Web Client',
        client_description: 'Axis VMS Web Client version x.x',
        token_endpoint_auth_method: 'client_secret_basic'
      }

      cy.createClientsRequest(this.readOnly.client_endpoint, body).then((response) => {
        expect(response.status).eq(400)
        expect(response.body.error).eq('invalid_client_metadata')
        expect(response.body.error_description).eq('redirect_uris[1] is not valid;redirect_uris[3] is not valid')
      })
    })

    it('[#3.2] Verify redirect is 302', function () {
      // https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16#section-4.11

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
      cy.getRequest(authorizationRequestUrl).then(response => {
        expect(response.status).to.eq(200)
        const authSessionId = cy.helpers.getSessionId(response.body)

        const body = {
          client_id: this.data.clientId,
          redirect_uri: this.data.redirectUris[0],
          auth_session_id: authSessionId,
          username: this.data.userName,
          password: this.data.password
        }

        cy.wait(2000)
        cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then(response => {
          // Expect successful response to be a 302 Found
          expect(response.status).to.eq(302)
          expect(response.headers.location).to.include('code=')

          cy.getRequest(authorizationRequestUrl).then(response => {
            expect(response.status).to.eq(200)
            const authSessionId = cy.helpers.getSessionId(response.body)

            const body = {
              client_id: this.data.clientId,
              redirect_uri: this.data.redirectUris[0],
              // Add suffix to session to make an invalid id
              auth_session_id: authSessionId + 'foobar',
              username: this.data.userName,
              password: this.data.password
            }

            cy.wait(2000)
            cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then(response => {
              // Expect unsuccessful response to be a 302 Found
              expect(response.status).to.eq(302)
              expect(response.headers.location).to.include('error=')
            })
          })
        })
      })
    })
  })

  /*
     * [#4.x] General
     *
     * Validations that verify a specific countermeasure that is not
     * necessarily unique for OIDC.
     * E.g. Verify rate limiting.
     */
  describe('[#4] General', function () {
    it('[#4.1] Verify request > 100 kB returns error', function () {
      // Maximum kB allowed for a request is set to 100 kB

      // Create a string which will repeat "Axis - OIDC IAM" 7000 times
      // This corresponds to approximately 105 kB which is invalid
      const longString = cy.helpers.repeatString('Axis - OIDC IAM', 7000)

      const item = {
        redirect_uris: ['https://oidcdebugger.com/debug'],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        application_type: 'web',
        client_name: 'AXIS VMS Web Client',
        client_description: 'Axis VMS Web Client version x.x',
        token_endpoint_auth_method: 'client_secret_basic',
        random_field: ['Axis - OIDC IAM' + longString]
      }

      // response.status will display 400 since we only support POST
      // request with size of 100 kB as maximum
      cy.createClientsRequest(this.readOnly.client_endpoint, item).then((response) => {
        expect(response.status).to.eq(400)
        expect(response.body.error).to.be.equal('too_large_request_body')
        expect(response.body.error_description).to.be.equal('Request body is too large')
      })
    })

    it('[#4.2] Verify that XSS attacks can not be applied to client_description', function () {
      // The script added to client_description is intended
      // to remove all the HTML in the login page, but will fail
      // since the templating will prevent it
      let body = {
        redirect_uris: ['https://oidcdebugger.com/debug'],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        application_type: 'web',
        client_name: 'AXIS VMS Web Client',
        client_description: '<script>document.documentElement.innerHTML=""</script>',
        token_endpoint_auth_method: 'client_secret_basic'
      }

      // Client registration
      cy.createClientsRequest(this.readOnly.client_endpoint, body).then((response) => {
        expect(response.status).to.eq(201)
        const clientDescription = response.body.client_description

        const params = {
          client_id: response.body.client_id,
          redirect_uri: response.body.redirect_uris[0],
          nonce: this.data.nonce,
          scope: 'openid',
          response_type: this.data.responseTypes,
          code_challenge: this.data.codeChallenge,
          code_challenge_method: 'S256',
          state: this.data.state
        }

        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)
        cy.visit(authorizationRequestUrl)
        cy.get('.description', {
          timeout: 30000
        }).should('have.text', clientDescription).and('be.visible')

        // Input valid username and password from oauthCred.json file
        cy.get('.username').type(this.data.userName)
        cy.get('.password').type(this.data.password)

        cy.wait(2000)

        // Click on the 'Login' button
        cy.get("[type='submit']").click()

        // Verify that response header displays correct URL
        cy.location().should((loc) => {
          const locationUrl = url.parse(loc.href, true)
          const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
          expect(host).eq(this.data.redirectUris[0])
          const query = locationUrl.query
          expect(query.code).to.match(/[a-zA-Z0-9-]+/)
          expect(query.iss).eq(this.data.issuer)
          expect(query.state).eq(this.data.state)
        })
      })

      cy.wait(2000)

      // The script added to client_description is intended to change
      // the title of the web page, but will fail since the templating
      // will prevent it
      body = {
        redirect_uris: ['https://oidcdebugger.com/debug'],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        application_type: 'web',
        client_name: 'AXIS VMS Web Client',
        client_description: '<script>document.title="The title has changed"</script>',
        token_endpoint_auth_method: 'client_secret_basic'
      }

      // Client registration
      cy.createClientsRequest(this.readOnly.client_endpoint, body).then((response) => {
        expect(response.status).to.eq(201)

        const params = {
          client_id: response.body.client_id,
          redirect_uri: response.body.redirect_uris[0],
          nonce: this.data.nonce,
          scope: 'openid',
          response_type: this.data.responseTypes,
          code_challenge: this.data.codeChallenge,
          code_challenge_method: 'S256',
          state: this.data.state
        }
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)
        cy.visit(authorizationRequestUrl)
        cy.title({
          timeout: 30000
        }).should('eq', 'Axis Local IAM')
      })

      cy.wait(2000)

      // The script added to client_description is intended to display
      // an alert box with 'XSS attack' as a string, but will fail
      // since the templating will prevent it

      body = {
        redirect_uris: ['https://oidcdebugger.com/debug'],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'],
        application_type: 'web',
        client_name: 'AXIS VMS Web Client',
        client_description: '<script>alert("XSS attack")</script>',
        token_endpoint_auth_method: 'client_secret_basic'
      }

      // Client registration
      cy.createClientsRequest(this.readOnly.client_endpoint, body).then((response) => {
        expect(response.status).to.eq(201)
        const clientDescription = response.body.client_description

        const params = {
          client_id: response.body.client_id,
          redirect_uri: response.body.redirect_uris,
          nonce: this.data.nonce,
          scope: 'openid',
          response_type: this.data.responseTypes,
          code_challenge: this.data.codeChallenge,
          code_challenge_method: 'S256',
          state: this.data.state
        }

        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

        cy.visit(authorizationRequestUrl)

        cy.wait(2000)
        cy.get('.description', {
          timeout: 30000
        }).should('have.text', clientDescription).and.visible
      })
    })

    it('[#4.3] Verify clickjacking is not possible', function () {
      // Clickjacking is when an attacker uses multiple transparent or opaque
      // layers to trick a user into clicking on a button or link on another
      // page when they were intending to click on the top level page.

      // https://tools.ietf.org/html/rfc6819#section-4.4.1.9

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

      // Creates an HTML file with code to if the login page can be loaded in
      // an iframe by creating a simple web page that includes a frame
      // containing the login page.  It should not be able to load the login
      // page in the iframe and displays a blank page
      cy.writeFile('security_test/clickJackingTest.html', '<html> <head> <title> CLICKJACKING TEST</title> </head> <body> <p> LOGIN PAGE </p> <iframe src=' +
                authorizationRequestUrl + 'width="500" height="500"> </iframe> </body> </html>')

      cy.visit('security_test/clickJackingTest.html')
      cy.wait(2000)
      cy.reload()
      cy.get('iframe').then($iframe => {
        const $body = $iframe.contents().find('body')
        cy.wrap($body).then($body => {
          // A web page which is not able to frame its context in an
          // iframe displays <body#t.neterror> in its body. This
          // applies only on browsers based on Chromium and the
          // X-frame-options is set to: DENY
          cy.get($body).should('have.class', 'neterror')
          cy.get($body).should('have.id', 't')
        })
      })
    })

    it('[#4.4] Verify that issuer is in the authorization response', function () {
      // https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16#section-4.4

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

        const body = {
          client_id: this.data.clientId,
          redirect_uri: this.data.redirectUris[0],
          auth_session_id: authSessionId,
          username: this.data.userName,
          password: this.data.password
        }

        cy.wait(2000)

        // Performs POST request which will submit the form-data
        cy.postRequest(this.readOnly.authorization_handle_endpoint, body).then((response) => {
          expect(response.status).to.eq(302)
          const locationUrl = url.parse(response.headers.location, true)
          expect(locationUrl.query.iss).eq(this.data.issuer)
        })
      })
    })

    it('[#4.5] POST and GET - test rate limit for request', function () {
      cy.wait(2000)
      const options = {
        url: this.readOnly.keys_endpoint,
        failOnStatusCode: false,
        headers: {
          Accept: 'application/json'
        }
      }
      cy.wrap(Array.from({
        length: 5
      })).each(() => {
        cy.request(options).then((response) => {
          expect(response.status).to.eq(200)
        })
      })

      cy.request(options).then((response) => {
        expect(response.status).to.eq(429)
        expect(response.body.error).eq('rate_limit')
        expect(response.body.error_description).eq('Too Many Requests')
      })

      // Verifies that the rate limit is still triggered
      cy.request(options).then((response) => {
        expect(response.status).to.eq(429)
        expect(response.body.error).eq('rate_limit')
        expect(response.body.error_description).eq('Too Many Requests')
      })

      // Verifies the rate limit has been reset after two seconds
      cy.wait(2000)
      cy.request(options).then((response) => {
        expect(response.status).to.eq(200)
      })
    })

    it('[#4.6] Verify that path traversal is not possible', function () {
      // Verify that the path to style.css exist
      cy.getRequest(this.readOnly.static_endpoint + '/style.css').then((response) => {
        expect(response.status).to.eq(200)
      })

      // Verify that you're not able to use path traversal
      // to access other files
      cy.getRequest(this.readOnly.static_endpoint + '/../').then((response) => {
        expect(response.status).to.eq(404)
        expect(response.body).to.eq('404 page not found\n')
      })

      // Verify that you're not able to use path traversal
      // to access a specific file
      cy.getRequest(this.readOnly.static_endpoint + '/../templates/service_documentation.tmpl').then((response) => {
        expect(response.status).to.eq(404)
        expect(response.body).to.eq('404 page not found\n')
      })
    })
  })
})
