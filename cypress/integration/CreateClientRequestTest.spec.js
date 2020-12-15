describe('Test CreateClient', function () {

    // Runs once before all tests in the block
    beforeEach(function () {

        // Fetch the data from the const.json file
        cy.fixture('const.json').then(function (data) {
            this.readOnly = data

            // Waits 2 seconds before each test
            // This is due to the rate limit set on all requests refilled per seconds
            // set to 3 and 1 respectively. If a cy.wait() is not added, it will fail the test
            // with a status code: 429 with error message: Error: "rate_limit", description: "Too Many Requests
            cy.wait(2000)

            cy.log('********* beforeEach has been successfully completed *********')
        })
    })

    it('Verify that redirect_uris with http returns error', function () {

        // Valid redirect_uri is set to https URL
        // The body in item is using an http URL which is not valid
        const item = {
            'redirect_uris': ['http://oidcdebugger.com/debug', 'http://axis.com'],
            'response_types': ['code'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'application_type': 'web',
            'client_name': 'AXIS VMS Web Client',
            'client_description': 'Axis VMS Web Client version x.x',
            'token_endpoint_auth_method': 'client_secret_basic'
        }

        cy.createClientsRequest(this.readOnly.client_endpoint, item)
            .then((response) => {
                expect(response.status).to.eq(400)
                expect(response.body.error).eq('invalid_client_metadata')
                expect(response.body.error_description).eq('redirect_uris[0] is not valid;redirect_uris[1] is not valid')
            })
    })

    it('Verify that redirect_uris with more than 2000 characters returns error', function () {

        // Maximum characters allowed for redirect_uris is set to 2000 characters

        // Will repeat the redirect_uris: ', https://oidcdebugger.com/debug' 66 times.
        // This corresponds to 2080 characters which is not valid
        const repeatRedirectUris = cy.helpers.repeatString(', https://oidcdebugger.com/debug', 65)

        const item = {
            'redirect_uris': ['https://oidcdebugger.com/debug' + repeatRedirectUris],
            'response_types': ['code'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'application_type': 'web',
            'client_name': 'AXIS VMS Web Client',
            'client_description': 'Axis VMS Web Client version x.x',
            'token_endpoint_auth_method': 'client_secret_basic'
        }

        cy.createClientsRequest(this.readOnly.client_endpoint, item)
            .then((response) => {
                expect(response.status).to.eq(400)
                expect(response.body.error).eq('invalid_client_metadata')
                expect(response.body.error_description).eq('redirect_uris[0] contains too many elements')
            })
    })

    it('Verify that response_types with more than 255 characters returns error', function () {

        // Maximum characters allowed for response_types is set to 255 characters
        // Will repeat the response_types: "code" 64 times
        // This corresponds to 256 characters which is not valid
        const repeatResponseTypes = cy.helpers.repeatString('code', 64)

        const item = {
            'redirect_uris': ['https://oidcdebugger.com/debug'],
            'response_types': [repeatResponseTypes],
            'grant_types': ['authorization_code', 'refresh_token'],
            'application_type': 'web',
            'client_name': 'AXIS VMS Web Client',
            'client_description': 'Axis VMS Web Client version x.x',
            'token_endpoint_auth_method': 'client_secret_basic'
        }

        cy.createClientsRequest(this.readOnly.client_endpoint, item)
            .then((response) => {
                expect(response.status).to.eq(400)
                expect(response.body.error).eq('invalid_client_metadata')
                expect(response.body.error_description).eq('response_types[0] contains too many elements')
            })
    })

    it('Verify that grant_types with more than 255 characters returns error', function () {

        // Maximum characters allowed for grant_types is set to 255 characters
        // Will repeat the grant_types: "authorization_code" 15 times
        // This corresponds to 256 characters which is not valid
        const repeatGrantTypes = cy.helpers.repeatString('authorization_code', 15)

        const item = {
            'redirect_uris': ['https://oidcdebugger.com/debug'],
            'response_types': ['code'],
            'grant_types': [repeatGrantTypes],
            'application_type': 'web',
            'client_name': 'AXIS VMS Web Client',
            'client_description': 'Axis VMS Web Client version x.x',
            'token_endpoint_auth_method': 'client_secret_basic'
        }

        cy.createClientsRequest(this.readOnly.client_endpoint, item)
            .then((response) => {
                expect(response.status).to.eq(400)
                expect(response.body.error).eq('invalid_client_metadata')
                expect(response.body.error_description).eq('grant_types[0] contains too many elements')
            })
    })

    it('Verify that application_types with more than 255 characters returns error', function () {

        // Maximum characters allowed for application_types is set to 255 characters
        // This function will repeat a string based on ones input

        // Will repeat the redirect_uris: "web" 86 times
        // This corresponds to 258 characters which is not valid
        const repeatGrantTypes = cy.helpers.repeatString('web', 86)

        const item = {
            'redirect_uris': ['https://oidcdebugger.com/debug'],
            'response_types': ['code'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'application_type': repeatGrantTypes,
            'client_name': 'AXIS VMS Web Client',
            'client_description': 'Axis VMS Web Client version x.x',
            'token_endpoint_auth_method': 'client_secret_basic'
        }

        cy.createClientsRequest(this.readOnly.client_endpoint, item)
            .then((response) => {
                expect(response.status).to.eq(400)
                expect(response.body.error).eq('invalid_client_metadata')
                expect(response.body.error_description).eq('application_type contains too many elements')
            })
    })

    it('Verify that empty client_name returns error', function () {

        // client_name has a minimum requriment of one character
        // client_name is set to empty
        const item = {
            'redirect_uris': ['https://oidcdebugger.com/debug'],
            'response_types': ['code'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'application_type': 'web',
            'client_name': '',
            'token_endpoint_auth_method': 'client_secret_basic'
        }

        cy.createClientsRequest(this.readOnly.client_endpoint, item)
            .then((response) => {
                expect(response.status).to.eq(400)
                expect(response.body.error).eq('invalid_client_metadata')
                expect(response.body.error_description).eq('client_name must have a value')
            })
    })

    it('Verify that client_name with more than 70 characters returns error', function () {

        // client_name is set to 71 characters which is not valid
        // The maximum requirement is set to 70 characters

        // Generate a random client_name which consist of 71 alphanumeric characters
        const clientName = cy.helpers.generateAlphanumerics(71)

        const item = {
            'redirect_uris': ['https://oidcdebugger.com/debug'],
            'response_types': ['code'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'application_type': 'web',
            'client_name': clientName,
            'token_endpoint_auth_method': 'client_secret_basic'
        }

        cy.createClientsRequest(this.readOnly.client_endpoint, item)
            .then((response) => {
                expect(response.status).to.eq(400)
                expect(response.body.error).eq('invalid_client_metadata')
                expect(response.body.error_description).eq('client_name contains too many elements')
            })
    })

    it('Verify that client_description with more than 255 characters returns error', function () {

        // client_description is optional to register

        // client_description is set to 256 characters which is not valid
        // The maximum length it allows is set to 255 characters

        // Generate a random client_description which consist of 256 alphanumeric characters
        const clientDescription = cy.helpers.generateAlphanumerics(256)

        // client_description is optional and its added with 256 characters
        const item = {
            'redirect_uris': ['https://oidcdebugger.com/debug'],
            'response_types': ['code'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'application_type': 'web',
            'client_name': 'AXIS VMS Web Client',
            'client_description': clientDescription,
            'token_endpoint_auth_method': 'client_secret_basic'
        }

        cy.createClientsRequest(this.readOnly.client_endpoint, item)
            .then((response) => {
                expect(response.status).to.eq(400)
                expect(response.body.error).eq('invalid_client_metadata')
                expect(response.body.error_description).eq('client_description contains too many elements')
            })
    })

    it('Verify that invalid token_endpoint_auth_method returns error', function () {

        // Valid token_endpoint_auth_method is set to: 'client_secret_basic'
        // The token_endpoint_auth_method in this item is set to: 'client_secret' which is invalid
        const item = {
            'redirect_uris': ['https://oidcdebugger.com/debug'],
            'response_types': ['code'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'application_type': 'web',
            'client_name': 'AXIS VMS Web Client',
            'client_description': 'Axis VMS Web Client version x.x',
            'token_endpoint_auth_method': 'client_secret'
        }

        cy.createClientsRequest(this.readOnly.client_endpoint, item)
            .then((response) => {
                expect(response.status).to.eq(400)
                expect(response.body.error).eq('invalid_client_metadata')
                expect(response.body.error_description).eq('token_endpoint_auth_method has an invalid value')
            })
    })

    it('Verify that client registration does not support public clients', function () {

        // Native clients are currently not supported since client registration
        // does not support public clients. "web" is currently the only supported application type.
        const item = {
            'redirect_uris': ['https://oidcdebugger.com/debug'],
            'response_types': ['code'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'application_type': 'native',
            'client_name': 'AXIS VMS Web Client',
            'client_description': 'Axis VMS Web Client version x.x',
            'token_endpoint_auth_method': 'client_secret_basic'
        }

        cy.createClientsRequest(this.readOnly.client_endpoint, item)
            .then((response) => {
                expect(response.status).to.eq(400)
                expect(response.body.error).eq('invalid_client_metadata')
                expect(response.body.error_description).eq('application_type failed on the validApplicationTypes rule')
            })
    })
})
