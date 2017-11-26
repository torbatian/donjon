const Boom = require('boom')
const Hoek = require('hoek')
const JWT = require('jsonwebtoken')

const internals = {}

internals.getToken = (request) => {
  const headerValue = request.headers['authorization']

  return headerValue ? headerValue.replace(/Bearer/gi, '').replace(/ /g, '') : null
}

exports.plugin = {
  once: true,
  pkg: require('../package.json'),

  register: (server, options) => {
    Hoek.assert(options, 'JWT authentication options is missing')
    Hoek.assert(typeof options.validate === 'function', 'options.validate must be a valid function')
    Hoek.assert(options.secret, 'options.secret must be a string')

    server.auth.scheme('jwt', {
      authenticate: (request, h) => {
        const token = internals.getToken(request)

        if (!token) {
          return Boom.unauthorized()
        }

        request.auth.token = token

        try {
          JWT.decode(token)
        } catch (error) {
          return Boom.unauthorized()
        }

        try {
          const verifyResult = JWT.verify(token, options.secret, options.verify || {})
          const validateResult = options.validate(verifyResult, request)

          if (!validateResult) {
            return Boom.unauthorized()
          }

          if (validateResult.isBoom) {
            return validateResult
          }

          return h.authenticated({credentials: validateResult})
        } catch (error) {
          return Boom.unauthorized()
        }
      }
    })
  }
}