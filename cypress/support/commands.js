// ***********************************************
// This example commands.js shows you how to
// create various custom commands and overwrite
// existing commands.
//
// For more comprehensive examples of custom
// commands please read more here:
// https://on.cypress.io/custom-commands
// ***********************************************
//
//
// -- This is a parent command --
Cypress.Commands.add('createClientsRequest', (url, item) => {
    cy.request({
        method: 'POST',
        url: url,
        failOnStatusCode: false,
        body: item,
        headers: {
            'Accept': 'application/json'
        }
    })
})

Cypress.Commands.add('deleteClientRequest', (url, uname, pass) => {
    cy.request({
        method: 'DELETE',
        url: url,
        failOnStatusCode: false,
        followRedirect: false,
        auth: {
            username: uname,
            password: pass,
        }
    })
})

Cypress.Commands.add('postRequest', (url, body) => {
    cy.request({
        method: 'POST',
        url: url,
        body: body,
        form: true,
        followRedirect: false,
        failOnStatusCode: false,
    })
})

Cypress.Commands.add('postAuthRequest', (url, uname, pass, body) => {
    cy.request({
        method: 'POST',
        url: url,
        body: body,
        form: true,
        failOnStatusCode: false,
        followRedirect: false,
        auth: {
            username: uname,
            password: pass,
        }
    })
})

Cypress.Commands.add('getRequest', (url) => {
    cy.request({
        method: 'GET',
        url: url,
        followRedirect: false,
        failOnStatusCode: false,
        headers: {
            'Content-Type': 'application/json'
        }
    })
})

Cypress.Commands.add('getAuthRequest', (url, token) => {
    cy.request({
        method: 'GET',
        url: url,
        followRedirect: false,
        failOnStatusCode: false,
        auth: {
            bearer: token
        }
    })
})

Cypress.Commands.add('generateAlphanumerics', (length) => {

    var alphanumeric = '';
    var possible = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

    for (var i = 0; i < length; i++) {
        alphanumeric += possible.charAt(Math.floor(Math.random() * possible.length))
    }
    return cy.wrap(alphanumeric);
})

Cypress.Commands.add('repeatString', (str, num) => {
    var totalString = '';
    if (num < 0) return '';

    for (var i = 0; i < num; i++) {
        totalString += str;
    }
    return cy.wrap(totalString);
})

Cypress.Commands.add('base64URLEncode', (str) => {

    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
})

Cypress.Commands.add('sha256', (buffer) => {

    const crypto = require('crypto')

    return crypto.createHash('sha256').update(buffer).digest();
})

Cypress.Commands.add('getSessionId', (buffer) => {

    const authSessionIdRegexp = /auth_session_id" value="([a-zA-Z0-9-]+)">/
    const res = authSessionIdRegexp.exec(buffer)

    return res[1]
})

Cypress.Commands.add('getAuthCode', (buffer) => {

    const authCodeRegexp = /\?code=([a-zA-Z0-9-]+)/
    const res = authCodeRegexp.exec(buffer['location'])

    return res[1]
})
//
//
// -- This is a child command --
// Cypress.Commands.add("drag", { prevSubject: 'element'}, (subject, options) => { ... })
//
//
// -- This is a dual command --
// Cypress.Commands.add("dismiss", { prevSubject: 'optional'}, (subject, options) => { ... })
//
//
// -- This will overwrite an existing command --
// Cypress.Commands.overwrite("visit", (originalFn, url, options) => { ... })
