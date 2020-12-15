const crypto = require('crypto')
const qs = require('querystring')
const url = require('url')

describe('Test GetLoginPage', function () {

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

                // Waits 2 seconds before each test.
                // This is due to the rate limit set on all requests refilled per seconds
                // set to 3 and 1 respectively. If a cy.wait() is not added, it will fail the test
                // with a status code: 429 with error message: Error: "rate_limit", description: "Too Many Requests
                cy.wait(2000)

                cy.log('********* beforeEach has been successfully completed *********')
            })
        })
    })

    it('Verify non registered client_id returns error', function () {

        // The client_id is invalid
        const params = {
            client_id: 'f82974c8-0352-49a9-9c67-72bef6bd1eea',
            redirect_uri: this.data.redirectUris[0],
            nonce: this.data.nonce,
            scope: 'openid',
            response_type: this.data.responseTypes,
            code_challenge: this.data.codeChallenge,
            code_challenge_method: 'S256',
            state: this.data.state
        }

        // Perform initial authentication request
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)
        cy.getRequest(authorizationRequestUrl).then((response) => {
            expect(response.status).to.eq(400)
            expect(response.body).eq('client_id does not exist\nredirect_uri is not registered on the client\n')
        })
    })

    it('Verify redirect_uri with no value returns error', function () {

        // redirect_uri has no value
        const params = {
            client_id: this.data.clientId,
            nonce: this.data.nonce,
            scope: 'openid',
            response_type: this.data.responseTypes,
            code_challenge: this.data.codeChallenge,
            code_challenge_method: 'S256',
            state: this.data.state
        }

        // Perform initial authentication request
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)
        cy.getRequest(authorizationRequestUrl).then((response) => {
            expect(response.status).to.eq(400)
            expect(response.body).eq('redirect_uri must have a value\n')
        })
    })

    it('Verify redirect_uri with more than 2000 characters returns error', function () {

        // Maximum characters allowed for redirect_uri is set to 2000 characters
        // This corresponds to 2010 characters which is not valid
        const repeatedRedirectUri = cy.helpers.repeatString(', https://oidcdebugger.com/debug', 67)

        const params = {
            client_id: this.data.clientId,
            redirect_uri: repeatedRedirectUri,
            nonce: this.data.nonce,
            scope: 'openid',
            response_type: this.data.responseTypes,
            code_challenge: this.data.codeChallenge,
            code_challenge_method: 'S256',
            state: this.data.state
        }

        // Perform initial authentication request    
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)
        cy.getRequest(authorizationRequestUrl).then((response) => {
            expect(response.status).to.eq(400)
            expect(response.body).to.eq('redirect_uri contains too many elements\n')
        })
    })

    it('Verify that nonce with less than 10 characters returns error', function () {

        // Nonce is set to nine characters which is not valid
        // The minimum requirement is set to ten characters
        const params = {
            client_id: this.data.clientId,
            redirect_uri: this.data.redirectUris[0],
            nonce: '123456789',
            scope: 'openid',
            response_type: this.data.responseTypes,
            code_challenge: this.data.codeChallenge,
            code_challenge_method: 'S256',
            state: this.data.state
        }
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

        // Perform initial authentication request
        cy.getRequest(authorizationRequestUrl).then((response) => {
            const locationUrl = url.parse(response.headers['location'], true)
            const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
            const query = locationUrl.query
            expect(response.status).to.eq(302)
            expect(host).eq(this.data.redirectUris[0])
            expect(query.error).eq('invalid_request')
            expect(query.error_description).eq('nonce does not contain enough elements')
            expect(query.iss).eq(this.data.issuer)
            expect(query.state).eq(this.data.state)
        })
    })

    it('Verify that nonce with more than 255 characters returns error', function () {

        // Maximum characters allowed for nonce is set to 255 characters
        const nonce = cy.helpers.generateAlphanumerics(256)
        const params = {
            client_id: this.data.clientId,
            redirect_uri: this.data.redirectUris[0],
            nonce: nonce,
            scope: 'openid',
            response_type: this.data.responseTypes,
            code_challenge: this.data.codeChallenge,
            code_challenge_method: 'S256',
            state: this.data.state
        }
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

        // Perform initial authentication request
        cy.getRequest(authorizationRequestUrl).then((response) => {
            const locationUrl = url.parse(response.headers['location'], true)
            const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
            const query = locationUrl.query
            expect(response.status).to.eq(302)
            expect(host).eq(this.data.redirectUris[0])
            expect(query.error).eq('invalid_request')
            expect(query.error_description).eq('nonce contains too many elements')
            expect(query.iss).eq(this.data.issuer)
            expect(query.state).eq(this.data.state)
        })
    })

    it('Verify that scope with more than 255 characters returns error ', function () {

        // Maximum characters allowed for scope is set to 255 characters
        // Will repeat the scope: 'openid' 43 times
        // This corresponds to 258 characters which is not valid
        const repeatScope = cy.helpers.repeatString('openid', 43)

        const params = {
            client_id: this.data.clientId,
            redirect_uri: this.data.redirectUris[0],
            nonce: this.data.nonce,
            scope: repeatScope,
            response_type: this.data.responseTypes,
            code_challenge: this.data.codeChallenge,
            code_challenge_method: 'S256',
            state: this.data.state
        }
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

        // Perform initial authentication request
        cy.getRequest(authorizationRequestUrl).then((response) => {
            const locationUrl = url.parse(response.headers['location'], true)
            const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
            const query = locationUrl.query
            expect(response.status).to.eq(302)
            expect(host).eq(this.data.redirectUris[0])
            expect(query.error).eq('invalid_request')
            expect(query.error_description).eq('scope[0] contains too many elements')
            expect(query.iss).eq(this.data.issuer)
            expect(query.state).eq(this.data.state)
        })
    })

    it('Verify that response_types that is not registered on the client returns error', function () {

        // The response_types that is registered on the client is 'code' from beforeEach()
        // Will repeat the response_types: "code" 2 times 
        const repeatResponseTypes = cy.helpers.repeatString('code', 2)

        const params = {
            client_id: this.data.clientId,
            redirect_uri: this.data.redirectUris[0],
            nonce: this.data.nonce,
            scope: 'openid',
            response_type: repeatResponseTypes,
            code_challenge: this.data.codeChallenge,
            code_challenge_method: 'S256',
            state: this.data.state
        }
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

        // Perform initial authentication request
        cy.getRequest(authorizationRequestUrl).then((response) => {
            const locationUrl = url.parse(response.headers['location'], true)
            const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
            const query = locationUrl.query
            expect(response.status).to.eq(302)
            expect(host).eq(this.data.redirectUris[0])
            expect(query.error).eq('invalid_request')
            expect(query.error_description).eq('response_type[0] is not registered on the client')
            expect(query.iss).eq(this.data.issuer)
            expect(query.state).eq(this.data.state)
        })
    })

    it('Verify that code_challenge with more than 128 characters returns error', function () {

        // code_challenge is set to 129 characters which is not valid
        // The maximum length it allows is set to 128 characters
        // Generate a random code_challenge which consist of 129 alphanumeric characters 
        const invalidCodeChallenge = cy.helpers.generateAlphanumerics(129)

        const params = {
            client_id: this.data.clientId,
            redirect_uri: this.data.redirectUris[0],
            nonce: this.data.nonce,
            scope: 'openid',
            response_type: this.data.responseTypes,
            code_challenge: invalidCodeChallenge,
            code_challenge_method: 'S256',
            state: this.data.state
        }
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

        // Perform initial authentication request
        cy.getRequest(authorizationRequestUrl).then((response) => {
            const locationUrl = url.parse(response.headers['location'], true)
            const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
            const query = locationUrl.query
            expect(response.status).to.eq(302)
            expect(host).eq(this.data.redirectUris[0])
            expect(query.error).eq('invalid_request')
            expect(query.error_description).eq('code_challenge contains too many elements')
            expect(query.iss).eq(this.data.issuer)
            expect(query.state).eq(this.data.state)
        })
    })

    it('Verify that code_challenge with less than 43 characters returns error', function () {

        // code_challenge is set to 42 characters which is not valid
        // The minimum length it allows is set to 43 characters
        // Generate a random code_challenge which consist of eleven alphanumeric characters 
        const invalidCodeChallenge = cy.helpers.generateAlphanumerics(42)

        const params = {
            client_id: this.data.clientId,
            redirect_uri: this.data.redirectUris[0],
            nonce: this.data.nonce,
            scope: 'openid',
            response_type: this.data.responseTypes,
            code_challenge: invalidCodeChallenge,
            code_challenge_method: 'S256',
            state: this.data.state
        }
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

        // Perform initial authentication request
        cy.getRequest(authorizationRequestUrl).then((response) => {
            const locationUrl = url.parse(response.headers['location'], true)
            const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
            const query = locationUrl.query
            expect(response.status).to.eq(302)
            expect(host).eq(this.data.redirectUris[0])
            expect(query.error).eq('invalid_request')
            expect(query.error_description).eq('code_challenge does not contain enough elements')
            expect(query.iss).eq(this.data.issuer)
            expect(query.state).eq(this.data.state)
        })
    })

    it('Verify that invalid code_challenge_method returns error', function () {

        // code_challenge_method only supports: S256 as a string
        const params = {
            client_id: this.data.clientId,
            redirect_uri: this.data.redirectUris[0],
            nonce: this.data.nonce,
            scope: 'openid',
            response_type: this.data.responseTypes,
            code_challenge: this.data.codeChallenge,
            code_challenge_method: 'S257',
            state: this.data.state
        }
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

        // Perform initial authentication request
        cy.getRequest(authorizationRequestUrl).then((response) => {
            const locationUrl = url.parse(response.headers['location'], true)
            const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
            const query = locationUrl.query
            expect(response.status).to.eq(302)
            expect(host).eq(this.data.redirectUris[0])
            expect(query.error).eq('invalid_request')
            expect(query.error_description).eq('code_challenge_method has an invalid value')
            expect(query.iss).eq(this.data.issuer)
            expect(query.state).eq(this.data.state)
        })
    })

    it('Verify that state with more than 1000 characters returns error', function () {

        // State is set to 1001 characters which is not valid
        // The maximum requirement is set to 1000 characters
        // Generate a random state which consist of 1001 alphanumeric characters
        const invalidState = cy.helpers.generateAlphanumerics(1001)

        const params = {
            client_id: this.data.clientId,
            redirect_uri: this.data.redirectUris[0],
            nonce: this.data.nonce,
            scope: 'openid',
            response_type: this.data.responseTypes,
            code_challenge: this.data.codeChallenge,
            code_challenge_method: 'S256',
            state: invalidState
        }
        const authorizationRequestUrl = this.readOnly.authorization_endpoint + qs.stringify(params)

        // Perform initial authentication request
        cy.getRequest(authorizationRequestUrl).then((response) => {
            const locationUrl = url.parse(response.headers['location'], true)
            const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
            const query = locationUrl.query
            expect(response.status).to.eq(302)
            expect(host).eq(this.data.redirectUris[0])
            expect(query.error).eq('invalid_request')
            expect(query.error_description).eq('state contains too many elements')
            expect(query.iss).eq(this.data.issuer)
            expect(query.state).eq(invalidState)
        })
    })
})