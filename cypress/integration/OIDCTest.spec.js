const crypto = require('crypto')
const qs = require('querystring')
const url = require('url')

describe('OIDC Testing', () => {
    beforeEach(function () {

        cy.wait(2000)

        Cypress.config('baseUrl', 'https://localhost:50120/v1/')

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

                // Waits 2 seconds before each test
                // This is due to the rate limit set on all requests refilled per seconds
                // set to 3 and 1 respectively. If a wait is not added, it will fail the test
                // with a status code: 429 with error message: Error: 'rate_limit', description: "Too Many Requests
                cy.wait(2000)

                cy.log('********* This is SETUP block *********')
            })
        })
    })

    it('GET - Redirect metadata route to latest version', function () {
        const requestMetadataUrl = 'https://localhost:50120/.well-known/openid-configuration'

        const options = {
            method: 'GET',
            url: requestMetadataUrl,
            followRedirect: true,
        }

        cy.request(options).then((response) => {
            expect(response.status).to.eq(200)
            expect(response.body.issuer).eq('https://localhost:50120')
            const issuer = response.body.issuer
            const version = '/v1'
            expect(response.body.authorization_endpoint).eq(issuer + version + '/authorize')
            expect(response.body.jwks_uri).eq(issuer + version + '/keys')
            expect(response.body.registration_endpoint).eq(issuer + version + '/clients')
            expect(response.body.service_documentation).eq(issuer + version + '/service-documentation')
            expect(response.body.token_endpoint).eq(issuer + version + '/token')
            expect(response.body.userinfo_endpoint).eq(issuer + version + '/userinfo')

            expect(response.body.scopes_supported).deep.eq(['openid'])
            expect(response.body.response_types_supported).deep.eq(['code'])
            expect(response.body.id_token_signing_alg_values_supported).deep.eq(['RS256'])
            expect(response.body.code_challenge_methods_supported).deep.eq(['S256'])
            expect(response.body.token_endpoint_auth_methods_supported).deep.eq(['client_secret_basic'])
        })
    })

    it('POST and GET - read and test metadata routes', function () {
        cy.request('GET', '/.well-known/openid-configuration').then((response) => {
            const scopesSupported = response.body.scopes_supported
            const responseTypesSupported = response.body.response_types_supported
            const codeChallengeMethodSupported = response.body.code_challenge_methods_supported
            const tokenEndpointAuthMethodSupported = response.body.token_endpoint_auth_methods_supported
            expect(response.status).to.eq(200)
            expect(response.body.issuer).eq('https://localhost:50120')
            expect(response.body.id_token_signing_alg_values_supported).deep.eq(['RS256'])
            expect(scopesSupported).deep.eq(['openid'])
            expect(responseTypesSupported).deep.eq(['code'])
            expect(codeChallengeMethodSupported).deep.eq(['S256'])
            expect(tokenEndpointAuthMethodSupported).deep.eq(['client_secret_basic'])

            // Verify service_documentation

            cy.visit(response.body.service_documentation)
            cy.get('#service-documentation-developer-overview').contains('Service Documentation (developer overview)').should('be.visible')

            const jwksUri = response.body.jwks_uri
            const registrationEndpoint = response.body.registration_endpoint
            const authorizationEndpoint = response.body.authorization_endpoint + '?'
            const tokenEndpoint = response.body.token_endpoint + '?'
            const userinfoEndpoint = response.body.userinfo_endpoint

            // Verify jwks_uri
            cy.wait(2000)
            cy.getRequest(jwksUri).then((response) => {
                expect(response.status).to.eq(200)
            })

            const registrationItem = {
                'redirect_uris': ['https://oidcdebugger.com/debug'],
                'response_types': responseTypesSupported,
                'grant_types': ['authorization_code', 'refresh_token'],
                'application_type': 'web',
                'client_name': 'AXIS VMS Web Client',
                'client_description': 'Axis VMS Web Client version x.x',
                'token_endpoint_auth_method': tokenEndpointAuthMethodSupported[0]
            }

            const options = {
                method: 'POST',
                url: registrationEndpoint,
                body: registrationItem,
            }

            // Performs a POST request where a client gets registered
            cy.request(options).then((response) => {
                const clientId = response.body.client_id
                const clientSecret = response.body.client_secret
                const redirectUri = response.body.redirect_uris[0]
                expect(response.status).to.eq(201)

                // Perform initial authentication request
                const params = {
                    client_id: clientId,
                    redirect_uri: redirectUri,
                    nonce: this.data.nonce,
                    scope: scopesSupported[0],
                    response_type: this.data.responseTypes,
                    code_challenge: this.data.codeChallenge,
                    code_challenge_method: codeChallengeMethodSupported[0],
                    state: this.data.state
                }

                const authorizationRequestUrl = authorizationEndpoint + qs.stringify(params)

                cy.wait(2000)
                cy.getRequest(authorizationRequestUrl).then((response) => {
                    expect(response.status).to.eq(200)

                    const authSessionId = cy.helpers.getSessionId(response.body)

                    const authHandleRequestUrl = this.readOnly.authorization_handle_endpoint
                    const body = {
                        client_id: clientId,
                        redirect_uri: this.data.redirectUris[0],
                        auth_session_id: authSessionId,
                        username: this.data.userName,
                        password: this.data.password
                    }

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

                        const tokenRequestUrl = tokenEndpoint
                        const body = {
                            grant_type: 'authorization_code',
                            code: query.code,
                            redirect_uri: this.data.redirectUris[0],
                            code_verifier: this.data.codeVerifier
                        }

                        // Perform token exchange
                        cy.wait(2000)
                        cy.postAuthRequest(tokenRequestUrl, clientId, clientSecret, body)
                            .then((response) => {
                                expect(response.status).to.eq(200)

                                // Performs a GET request which will fetch the userinfo
                                cy.getAuthRequest(userinfoEndpoint, response.body.access_token)
                                    .then((response) => {
                                        expect(response.status).eq(200)
                                    })
                            })
                    })
                })
            })
        })
    })

    it('GET - userinfo', function () {

        // The userinfo endpoint returns username and group information related to
        // the authenticated user. Authentication is done via access token as
        // bearer header.
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

                        const userinfo = '/userinfo'
                        const refresh_token = response.body.refresh_token

                        // Performs a GET request which will fetch the userinfo
                        cy.getAuthRequest(userinfo, response.body.access_token).then((response) => {
                            expect(response.status).eq(200)
                            expect(response.body.sub).eq(this.data.userName)
                            expect(response.body.groups).deep.equal(['Users'])
                        })

                        // Refresh token
                        const refreshTokenRequestUrl = this.readOnly.token_endpoint
                        const body = {
                            grant_type: 'refresh_token',
                            refresh_token: refresh_token
                        }

                        cy.wait(2000)
                        cy.postAuthRequest(refreshTokenRequestUrl, this.data.clientId, this.data.clientSecret, body)
                            .then((response) => {
                                expect(response.status).to.eq(200)

                                // Performs another GET request which will
                                // fetch the userinfo after the token has
                                // been refreshed
                                cy.getAuthRequest(userinfo, response.body.access_token)
                                    .then((response) => {
                                        expect(response.status).eq(200)
                                        expect(response.body.sub).eq(this.data.userName)
                                        expect(response.body.groups).deep.equal(['Users'])
                                    })
                            })
                    })
            })
        })
    })

    it('GET - read keys', () => {
        cy.request('GET', '/keys').then((response) => {
            expect(response.status).to.eq(200)
            expect(response.body).to.not.be.null
            expect(response.body.keys[0]).has.property('alg', 'RS256', 'kty', 'RSA', 'e', 'AQAB')
        })
    })

    it('POST - create clients', function () {
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
            expect(response.status).to.eq(201)
            expect(response.body).to.not.be.null
            expect(response.body.client_id).to.not.be.null
            expect(response.body.redirect_uris).deep.equal(['https://oidcdebugger.com/debug'])
            expect(response.body.response_types).deep.equal(['code'])
            expect(response.body.grant_types).deep.equal(['authorization_code', 'refresh_token'])
            expect(response.body.application_type).eq('web')
            expect(response.body.client_name).eq('AXIS VMS Web Client')
            expect(response.body.client_description).eq('Axis VMS Web Client version x.x')
            expect(response.body.client_secret).to.not.be.null
            expect(response.body.client_secret_expires_at).eq(0)
        })
    })
})