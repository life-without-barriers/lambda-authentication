const { resetModules } = jest

beforeEach(() => {
  resetModules()
})

const getDefaultJwtPayload = () => {
  const now = new Date()
  return {
    iss: 'https://foo.bar.com',
    aud: 'app1',
    iat: Math.floor(new Date(
      now.getFullYear() - 2,
      now.getMonth(),
      now.getDate()
    ).getTime() / 1000),
    exp: Math.floor(new Date(
      now.getFullYear(),
      now.getMonth() + 1,
      now.getDate()
    ).getTime() / 1000),
    sub: 'foo@bar.com'
  }
}

describe('authorizer', () => {
  it('should reject no auth token', () => {
    const authorizer = require('./authorizer').default

    const { error, message } = authorizer({
      methodArn: 'bar'
    })
    expect(message).toEqual('Unauthorized')
    expect(error).toEqual('No authorization token present')
  })

  it('should reject an invalid header', () => {
    const authorizer = require('./authorizer').default

    const { error, message } = authorizer({
      authorizationToken: 'foo',
      methodArn: 'bar',
      cookieName: 'foo'
    })
    expect(message).toEqual('Unauthorized')
    expect(error).toEqual('Invalid Cookie Header')
  })

  it('should reject an invalid jwt', () => {
    const authorizer = require('./authorizer').default

    const { message, error } = authorizer({
      authorizationToken: 'jwt=foo',
      methodArn: 'bar',
      cookieName: 'jwt',
      secret: 'secret'
    })
    expect(message).toEqual('Unauthorized')
    expect(error.message).toEqual('jwt malformed')
  })

  it('should reject an invalid signature', () => {
    const signed = require('jsonwebtoken').sign(getDefaultJwtPayload(), 'imwrong')

    const authorizer = require('./authorizer').default

    const { message, error } = authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      cookieName: 'foo',
      secret: 'secret'
    })

    expect(message).toEqual('Unauthorized')
    expect(error.message).toEqual('invalid signature')
  })

  it('should reject a missing cookie name', () => {
    const signed = require('jsonwebtoken').sign(getDefaultJwtPayload(), 'secret')

    const authorizer = require('./authorizer').default

    const { message, error } = authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      cookieName: 'nope',
      secret: 'secret'
    })

    expect(message).toEqual('Unauthorized')
    expect(error).toEqual('nope not found in cookies')
  })

  it('should reject expired token', () => {
    const payload = getDefaultJwtPayload()
    const now = new Date()
    payload.exp = Math.floor(new Date(
      now.getFullYear() - 1,
      now.getMonth(),
      now.getDate()
    ).getTime() / 1000)

    const signed = require('jsonwebtoken').sign(payload, 'secret')
    const authorizer = require('./authorizer').default

    const { message, error } = authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      audience: 'app1',
      cookieName: 'foo',
      secret: 'secret'
    })
    expect(message).toEqual('Unauthorized')
    expect(error.message).toEqual('jwt expired')
  })

  it('should reject token with wrong aud', () => {
    const payload = getDefaultJwtPayload()

    const signed = require('jsonwebtoken').sign(payload, 'secret')
    const authorizer = require('./authorizer').default

    const { message, error } = authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      audience: 'app2',
      cookieName: 'foo',
      secret: 'secret'
    })
    expect(error.message).toEqual('jwt audience invalid. expected: app2')
    expect(message).toEqual('Unauthorized')
  })

  it('should reject token with wrong iss', () => {
    const signed = require('jsonwebtoken').sign(getDefaultJwtPayload(), 'secret')
    const authorizer = require('./authorizer').default

    const { message, error } = authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      audience: 'app1',
      cookieName: 'foo',
      issuer: 'nope',
      secret: 'secret'
    })
    expect(error.message).toEqual('jwt issuer invalid. expected: nope')
    expect(message).toEqual('Unauthorized')
  })

  it('should reject token without sub claim', () => {
    let payload = getDefaultJwtPayload()
    payload.sub = null
    const signed = require('jsonwebtoken').sign(payload, 'secret')
    const authorizer = require('./authorizer').default

    const { message, error } = authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      cookieName: 'foo',
      secret: 'secret'
    })
    expect(error).toEqual('sub is a required claim')
    expect(message).toEqual('Unauthorized')
  })

  it('should validate a valid token', () => {
    const signed = require('jsonwebtoken').sign(getDefaultJwtPayload(), 'secret')
    const authorizer = require('./authorizer').default

    const { policy } = authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'arn:aws:execute-api:us-east-1:123456789012:qsxrty/foo/GET/api/service-agreements/',
      path: '/api/cats',
      audience: 'app1',
      cookieName: 'foo',
      secret: 'secret'
    })

    expect(policy).toBeDefined()
    expect(policy).toMatchObject({
      principalId: 'foo@bar.com',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [{
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: [
            'arn:aws:execute-api:us-east-1:123456789012:qsxrty/foo/*/api/cats',
            'arn:aws:execute-api:us-east-1:123456789012:qsxrty/foo/*/api/cats/*'
          ]
        }]
      }
    })
  })
})
