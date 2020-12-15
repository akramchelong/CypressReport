const crypto = require('crypto')
const qs = require('querystring')
const url = require('url')

describe('Test DeleteClient', function () {

    // Runs once before all tests in the block
    beforeEach(function () {

        // Waits 2 seconds before each test
        // This is due to the rate limit set on all requests refilled per seconds
        // set to 3 and 1 respectively. If a cy.wait() is not added, it will fail the test
        // with a status code: 429 with error message: Error: "rate_limit", description: "Too Many Requests
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
                'redirect_uris': ['https://oidcdebugger.com/debug'],
                'response_types': ['code'],
                'grant_types': ['authorization_code', 'refresh_token'],
                'application_type': 'web',
                'client_name': 'AXIS VMS Web Client',
                'client_description': 'Axis VMS Web Client version x.x',
                'token_endpoint_auth_method': 'client_secret_basic'
            }

            cy.createClientsRequest(this.readOnly.client_endpoint, item).then((response) => {
                this.data.clientId = response.body.client_id
                this.data.clientSecret = response.body.client_secret
                this.data.redirectUris = response.body.redirect_uris
                this.data.responseTypes = response.body.response_types
                this.data.clientName = response.body.client_name
                this.data.clientDescription = response.body.client_description
                this.data.state = 'home'

                cy.wait(2000)

                cy.log('********* beforeEach has been successfully completed *********')
            })
        })
    })

    it('Verify that client id gets deleted and cant be used in authorize request', function () {

        // Performs a DELETE request of the client id registrered
        const deleteRequestUrl = this.readOnly.client_endpoint + '/' + this.data.clientId
        cy.log(deleteRequestUrl)
        cy.deleteClientRequest(deleteRequestUrl, this.data.clientId, this.data.clientSecret)
            .then((response) => {
                expect(response.status).to.eq(204)

                // Performs a GET request with compulsory data in order to get
                // the login page of authorization server. In this case it will
                // fail since the client id has been deleted
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

                // Perform initial authentication request. In this case it will
                // fail since the client id has been deleted
                cy.getRequest(authorizationRequestUrl).then((response) => {
                    expect(response.status).to.eq(400)
                    expect(response.body).eq('client_id does not exist\nredirect_uri is not registered on the client\n')
                })
            })
    })

    it('Verify that client id gets deleted and cant be used in handle request', function () {

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

            cy.wait(2000)

            // Performs a DELETE request of the client id registered
            const deleteRequestUrl = this.readOnly.client_endpoint + '/' + this.data.clientId
            cy.deleteClientRequest(deleteRequestUrl, this.data.clientId, this.data.clientSecret)
                .then((response) => {
                    expect(response.status).to.eq(204)
                })

            // Performs POST request which submits the form-data
            // In this case it will fail since the client id has been deleted
            const authHandleRequestUrl = this.readOnly.authorization_handle_endpoint
            const body = {
                client_id: this.data.clientId,
                redirect_uri: this.data.redirectUris[0],
                auth_session_id: authSessionId,
                username: this.data.userName,
                password: this.data.password
            }

            cy.postRequest(authHandleRequestUrl, body).then((response) => {
                expect(response.status).to.eq(400)
                expect(response.body).eq('client_id does not exist\nredirect_uri is not registered on the client\n')
            })
        })
    })

    it('Verify that client id gets deleted and cant be used in token request', function () {

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
                const locationUrl = url.parse(response.headers['location'], true)
                const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
                const query = locationUrl.query
                expect(response.status).to.eq(302)
                expect(host).eq(this.data.redirectUris[0])
                expect(query.code).to.match(/[a-zA-Z0-9-]+/)
                expect(query.iss).eq(this.data.issuer)
                expect(query.state).eq(this.data.state)

                // Performs a DELETE request of the client id registrered
                const deleteRequestUrl = this.readOnly.client_endpoint + '/' + this.data.clientId
                cy.deleteClientRequest(deleteRequestUrl, this.data.clientId, this.data.clientSecret)
                    .then((response) => {
                        expect(response.status).to.eq(204)
                    })

                // Perform token exchange
                // In this case it will be invalid since the client id has been deleted
                const tokenRequestUrl = this.readOnly.token_endpoint
                const body = {
                    grant_type: 'authorization_code',
                    code: query.code,
                    redirect_uri: this.data.redirectUris[0],
                    code_verifier: this.data.codeVerifier
                }

                cy.wait(2000)
                cy.postAuthRequest(tokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
                    .then((response) => {
                        expect(response.status).to.eq(401)
                        expect(response.body.error).eq('invalid_client')
                        expect(response.body.error_description).eq('Missing or invalid authorization header')
                    })
            })
        })
    })

    it('Verify that client id gets deleted and cant be used in refresh token request', function () {

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
                const locationUrl = url.parse(response.headers['location'], true)
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
                cy.postAuthRequest(tokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
                    .then((response) => {
                        expect(response.status).to.eq(200)
                        const refreshToken = response.body.refresh_token

                        // Performs a DELETE request of the client id registrered
                        const deleteRequestUrl = this.readOnly.client_endpoint + '/' + this.data.clientId
                        cy.deleteClientRequest(deleteRequestUrl, this.data.clientId, this.data.clientSecret)
                            .then((response) => {
                                expect(response.status).to.eq(204)
                            })

                        // Refresh token
                        // In this case it will be invalid since the client id has been deleted
                        const refreshTokenRequestUrl = this.readOnly.token_endpoint
                        const body = {
                            grant_type: 'refresh_token',
                            refresh_token: refreshToken
                        }

                        cy.postAuthRequest(refreshTokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
                            .then((response) => {
                                expect(response.status).to.eq(401)
                                expect(response.body.error).eq('invalid_client')
                                expect(response.body.error_description).eq('Missing or invalid authorization header')
                            })
                    })
            })
        })
    })

    it('Verify that client id gets deleted and cant be used in the second refresh token request', function () {

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
                const locationUrl = url.parse(response.headers['location'], true)
                const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
                const query = locationUrl.query
                expect(response.status).to.eq(302)
                expect(host).eq(this.data.redirectUris[0])
                expect(query.code).to.match(/[a-zA-Z0-9-]+/)
                expect(query.iss).eq(this.data.issuer)
                expect(query.state).eq(this.data.state)

                // Perform token exchange
                const tokenRequestUrl = this.readOnly.token_endpoint
                const body = {
                    grant_type: 'authorization_code',
                    code: query.code,
                    redirect_uri: this.data.redirectUris[0],
                    code_verifier: this.data.codeVerifier
                }

                cy.wait(2000)
                cy.postAuthRequest(tokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
                    .then((response) => {
                        expect(response.status).to.eq(200)

                        // Refresh token
                        const refreshToken = response.body.refresh_token
                        const refreshTokenRequestUrl = this.readOnly.token_endpoint
                        const body = {
                            grant_type: 'refresh_token',
                            refresh_token: refreshToken
                        }

                        // Performs a POST request which will refresh the token
                        cy.postAuthRequest(refreshTokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
                            .then((response) => {
                                expect(response.status).to.eq(200)
                                const refreshToken = response.body.refresh_token

                                // Performs a DELETE request of the client id registrered
                                const deleteRequestUrl = this.readOnly.client_endpoint + '/' + this.data.clientId
                                cy.deleteClientRequest(deleteRequestUrl, this.data.clientId, this.data.clientSecret)
                                    .then((response) => {
                                        expect(response.status).to.eq(204)
                                    })

                                // Perform second token exchange
                                // In this case it will be invalid since the client id has been deleted
                                const refreshTokenRequestUrl = this.readOnly.token_endpoint
                                const body = {
                                    grant_type: 'refresh_token',
                                    refresh_token: refreshToken
                                }

                                cy.wait(2000)
                                cy.postAuthRequest(refreshTokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
                                    .then((response) => {
                                        expect(response.status).to.eq(401)
                                        expect(response.body.error).eq('invalid_client')
                                        expect(response.body.error_description).eq('Missing or invalid authorization header')
                                    })
                            })
                    })
            })
        })
    })
})