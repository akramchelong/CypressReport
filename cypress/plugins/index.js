// ***********************************************************
// This example plugins/index.js can be used to load plugins
//
// You can change the location of this file or turn off loading
// the plugins file with the 'pluginsFile' configuration option.
//
// You can read more here:
// https://on.cypress.io/plugins-guide
// ***********************************************************
const path = require('path')

// This function is called when a project is opened or re-opened (e.g. due to
// the project's config changing)

/**
 * @type {Cypress.PluginConfig}
 */
module.exports = (on, config) => {
  // `on` is used to hook into various events Cypress emits
  // `config` is the resolved Cypress config

  // Cypress terminal report
  require('cypress-terminal-report/src/installLogsPrinter')(on)
  on('before:browser:launch', (browser, launchOptions) => {
    if (browser.family === 'chromium' && browser.name !== 'electron') {
      // provide absolute path to unpacked extension's folder
      const extension = path.resolve('./gleekbfjekiniecknbkamfmkohkpodhe')
      console.log(extension)
      launchOptions.extensions.push(extension)
    }

    return launchOptions
  })
}
