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

    expect(() => authorizer({
      methodArn: 'bar'
    })).toThrow(/No\sauthorization\stoken\spresent/)
  })

  it('should reject an invalid header', () => {
    const authorizer = require('./authorizer').default

    expect(() => authorizer({
      authorizationToken: 'foo',
      methodArn: 'bar',
      cookieName: 'foo'
    })).toThrow(/Invalid\sCookie\sHeader/)
  })

  it('should reject an invalid jwt', () => {
    const authorizer = require('./authorizer').default

    expect(() => authorizer({
      authorizationToken: 'jwt=foo',
      methodArn: 'bar',
      cookieName: 'jwt',
      secret: 'secret'
    })).toThrow(/jwt\smalformed/)
  })

  it('should reject an invalid signature', () => {
    const signed = require('jsonwebtoken').sign(getDefaultJwtPayload(), 'imwrong')

    const authorizer = require('./authorizer').default

    expect(() => authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      cookieName: 'foo',
      secret: 'secret'
    })).toThrow(/invalid\ssignature/)
  })

  it('should reject a missing cookie name', () => {
    const signed = require('jsonwebtoken').sign(getDefaultJwtPayload(), 'secret')

    const authorizer = require('./authorizer').default

    expect(() => authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      cookieName: 'nope',
      secret: 'secret'
    })).toThrow(/nope\snot\sfound\sin\scookies/)
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

    expect(() => authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      audience: 'app1',
      cookieName: 'foo',
      secret: 'secret'
    })).toThrow(/jwt\sexpired/)
  })

  it('should reject token with wrong aud', () => {
    const payload = getDefaultJwtPayload()

    const signed = require('jsonwebtoken').sign(payload, 'secret')
    const authorizer = require('./authorizer').default

    expect(() => authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      audience: 'app2',
      cookieName: 'foo',
      secret: 'secret'
    })).toThrow(/jwt\saudience\sinvalid\.\sexpected:\sapp2/)
  })

  it('should reject token with wrong iss', () => {
    const signed = require('jsonwebtoken').sign(getDefaultJwtPayload(), 'secret')
    const authorizer = require('./authorizer').default

    expect(() => authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      audience: 'app1',
      cookieName: 'foo',
      issuer: 'nope',
      secret: 'secret'
    })).toThrow(/jwt\sissuer\sinvalid\.\sexpected:\snope/)
  })

  it('should reject token without sub claim', () => {
    let payload = getDefaultJwtPayload()
    payload.sub = null
    const signed = require('jsonwebtoken').sign(payload, 'secret')
    const authorizer = require('./authorizer').default

    expect(() => authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      cookieName: 'foo',
      secret: 'secret'
    })).toThrow(/sub\sis\sa\srequired\sclaim/)
  })

  it('should validate a valid token', () => {
    const signed = require('jsonwebtoken').sign(getDefaultJwtPayload(), 'secret')
    const authorizer = require('./authorizer').default

    const policy = authorizer({
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
