const crypto = require('crypto')
const qs = require('querystring')
const url = require('url')

describe('Test AuthHandle', function () {
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

      cy.createClientsRequest(this.readOnly.client_endpoint, item)
        .then((response) => {
          this.data.clientId = response.body.client_id
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

  it('Verify username and password with more than 250 characters returns error', function () {
    // username and password is set to 256 characters which is not valid
    // The maximum length it allows is set to 255 characters each
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

    // Generate alphanumeric string which consist of 256 characters
    // that will be used as credential input
    const invalidCred = cy.helpers.generateAlphanumerics(256)

    cy.visit(authorizationRequestUrl)

    // Input valid username and password from oauthCred.json file
    cy.get('.username').type(invalidCred)
    cy.get('.password').type(invalidCred)

    // Click on the 'Login' button
    cy.get("[type='submit']").click()

    // Verify that response header displays correct URL
    cy.location().should((loc) => {
      const locationUrl = url.parse(loc.href, true)
      const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
      expect(host).eq(this.data.redirectUris[0])
      const query = locationUrl.query
      expect(query.error).eq('invalid_request')
      expect(query.error_description).eq('password contains too many elements,username contains too many elements')
      expect(query.iss).eq(this.data.issuer)
      expect(query.state).eq(this.data.state)
    })
  })

  it('Verify that invalid access credentials returns error', function () {
    // Both username and password has a maximum length limit set to 250 characters each
    // Performs a GET request with compulsory data in order to get redirected to the login page of OIDC
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
    cy.visit(authorizationRequestUrl)

    // Input valid username and password from oauthCred.json file
    cy.get('.username').type('invalidCred')
    cy.get('.password').type('invalidCred')

    cy.wait(2000)

    // Click on the 'Login' button
    cy.get("[type='submit']").click()

    // Verify the alert box displays correct message
    cy.get('.alert').should('have.text', 'Incorrect credentials').and('be.visible')

    // Verify that response header displays correct URL
    cy.location().should((loc) => {
      const locationUrl = url.parse(loc.href, true)
      const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
      expect(host).eq(this.readOnly.authorization_handle_endpoint)
    })
  })

  it('Verify that empty credentials returns error', function () {
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
    cy.visit(authorizationRequestUrl)

    cy.wait(2000)

    // Click on the 'Login' button
    cy.get("[type='submit']").click()

    // Verify the alert box displays correct message
    cy.get('.alert').should('have.text', 'Incorrect credentials').and('be.visible')

    // Verify that response header displays correct URL
    cy.location().should((loc) => {
      const locationUrl = url.parse(loc.href, true)
      const host = locationUrl.protocol + '//' + locationUrl.host + locationUrl.pathname
      expect(host).eq(this.readOnly.authorization_handle_endpoint)
    })
  })

  it('Verify a successful login', function () {
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
    cy.visit(authorizationRequestUrl)

    // Verify it displays the correct information in the login page
    cy.get('.title').should('have.text', this.data.clientName).and('be.visible')
    cy.get('.formTitle').should('have.text', 'Login').and('be.visible')
    cy.get('.description').should('have.text', this.data.clientDescription).and('be.visible')
    cy.get('.redirect-info-label').should('have.text', 'Authenticating will redirect to').and('be.visible')
    cy.get('.redirect-info-uri').should('have.text', this.data.redirectUris[0]).and('be.visible')
    cy.get('.MuiTypography-root-301').should('have.text', '1.0').and('be.visible')

    // Verify that the Axis Communications logo is visible
    cy.get('svg').should('be.visible')

    // Input valid username and password from oauthCred.json file
    cy.get('.username').type(this.data.userName)
    cy.get('.password').type(this.data.password)

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
})
