const j = require('pem-jwk')
const { resetModules, mock } = jest

beforeEach(() => {
  resetModules()
})

const keys = [{'alg': 'RS256', 'e': 'AQAB', 'n': 'gUh6FTPyISKDH6YmxllUqV_7AsibC1UKOWX-3nhjZ1pl5qPmTrrHx1XepZ4V_AmJACDjPeUwHAipgz8oEC3W5T_L-SltGkeWV2EvZneUhQim_-7qngFwICeic8Vh04V1M4sgcbcvq1E5sfV9lDot0WEiovyYs8BD4G9Z9768vr81CqvEFnaYfrzNZ9X4DwE6r7PTik-2-rbks_YX12dvbP9_lNpXHcZC4C2E6BJNBHW1w5LozmDFm2hsqQrbyZVjxiREZez3KJf5Avzb3qzuWzPqIfl-8-DNOfXqq7j5rt420lXycLVQ_AS4LnMsNtO3LWrNK-vc7eya3jz2JakH6Q', 'kid': 'WL0tKDcoDxMv7rtRPkKDF4O7TBoG5WqynmXQ11EYlWc', 'kty': 'RSA', 'use': 'sig'}]
const invalidKid = `foo=eyJhbGciOiJSUzI1NiIsImtpZCI6IldMMHRLRGNvRHhNdjdydDJQa0tERjRPN1RCb0s2V3F5bm1YUTExRVlsV2MifQ.eyJzdWIiOiIwMHUxaXRhZnU1ZG5Pb0hqNDF0NyIsImVtYWlsIjoiTWF0dGhldy5NdXJwaHlAbHdiLm9yZy5hdSIsInZlciI6MSwiaXNzIjoiaHR0cHM6Ly9sd2Iub2t0YS5jb20iLCJhdWQiOiI3eHRsMTVQYnRVZVlnYzY5bXN3RSIsImlhdCI6MTQ4OTAxNTA1MywiZXhwIjoxNDg5MDE4NjUzLCJqdGkiOiJJRC5ILTdlaVBJWElsd2JIelFocmFhWElIWEFQZHpkT1phRnRKX0NuamJ3N0lRIiwiYW1yIjpbInB3ZCJdLCJpZHAiOiIwMG8xaXRhZnRkN1FMTXgxTTF0NyIsImF1dGhfdGltZSI6MTQ4OTAxNTA1MSwiYXRfaGFzaCI6IkQ1UjloY3NOMGFYQ2I0S2VVRmVJU1EifQ.S1rOoIM_ky4mZcwcHo1qCx24Qaa8rJNQ6yCSAh35rqcwsLPQX7R72nMFDb0S4E2CiTKO7f-gepzmGux54JHYkPmFAGVQb5WiBeibhEKAYf2MCmEPG5LPhXUIdLa8sFKADlNk5YXwRGFgvOLN3NkQX_SyAeDD6ginNEkxSXZrcpIKVFkk203t1v7a2mR42B63-5w8tzYqDovpK9SeW19ThfaE5oU-WuEM4QByhN8e8lZw4GCVw7QvOPuvZvMquS0X5vAsWGGyzKDC4RRS8KgVQreif5XfOKciuzVMPa7lA3qj6JLp6ddFGQmJC0Qq5LZWaTJ_SwT9ECxHF6RbWAQuEg`
const invalidSignature = `foo=eyJhbGciOiJSUzI1NiIsImtpZCI6IldMMHRLRGNvRHhNdjdydFJQa0tERjRPN1RCb0c1V3F5bm1YUTExRVlsV2MifQ.eyJzdWIiOiIwMHUxaXRhZnU1ZG5Pb0hqNDF0NyIsImVtYWlsIjoiTWF0dGhldy5NdXJwaHlAbHdiLm9yZy5hdSIsInZlciI6MSwiaXNzIjoiaHR0cHM6Ly9sd2Iub2t0YS5jb20iLCJhdWQiOiI3eHRsMTVQYnRVZVlnYzY5bXN3RSIsImlhdCI6MTQ4OTAxNTA1MywiZXhwIjoxNDg5MDE4NjUzLCJqdGkiOiJJRC5ILTdlaVBJWElsd2JIelFocmFhWElIWEFQZHpkT1phRnRKX0NuamJ3N0lRIiwiYW1yIjpbInB3ZCJdLCJpZHAiOiIwsG8xaXRhZnRkN1FMTXgxTTF0NyIsImF1dGhfdGltZSI6MTQ4OTAxNTA1MSwiYXRfaGFzaCI6IkQ1UjloY3NOMGFYQ2I0S2VVRmVJU1EifQ.S1rOoIM_ky4mZcwcHo1qCx24Qaa8rJNQ6yCSAh35rqcwsLPQX7R72nMFDb0S4E2CiTKO7f-gepzmGux54JHYkPmFAGVQb5WiBeibhEKAYf2MCmEPG5LPhXUIdLa8sFKADlNk5YXwRGFgvOLN3NkQX_SyAeDD6ginNEkxSXZrcpIKVFkk203t1v7a2mR42B63-5w8tzYqDovpK9SeW19ThfaE5oU-WuEM4QByhN8e8lZw4GCVw7QvOPuvZvMquS0X5vAsWGGyzKDC4RRS8KgVQreif5XfOKciuzVMPa7lA3qj6JLp6ddFGQmJC0Qq5LZWaTJ_SwT9ECxHF6RbWAQuEg`
const publicKey = j.pem2jwk(`
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyulxl/DHwuK0oosBlJbicC25+fuyQfOmlrfBuwccjhlBsGUMwPYc
otQAbmjt1sjaPgTG59Oz4GF6iAVXKxbhTFCAbLrz08PjDM3Qeoz/EpO25zCSO4NM
MuLvienEnXh1js9F3NDdDxTW+FoeMX9NuDUSWs0fkhmqUWoQebeFBHFK8bHRAOYm
w2Ty3s8icbCMYplrcte0eh29gnz4CWWNmCl0u3FVibBCx5HJpJHu+32xjOWEIF2d
gP8V1W91KF0PNAODclkVD1MyM8zFOKYvMhekMJGOmkRyK9ljd0/TNU3xHeDvaHTy
vT8WWzEFgObhXXaA2nY38FL1bdG6Z9qM5QIDAQAB
-----END RSA PUBLIC KEY-----`
)
publicKey.kid = 'WL0tKDcoDxMv7rtRPkKDF4O7TBoG5WqynmXQ11EYlWc'
const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAyulxl/DHwuK0oosBlJbicC25+fuyQfOmlrfBuwccjhlBsGUM
wPYcotQAbmjt1sjaPgTG59Oz4GF6iAVXKxbhTFCAbLrz08PjDM3Qeoz/EpO25zCS
O4NMMuLvienEnXh1js9F3NDdDxTW+FoeMX9NuDUSWs0fkhmqUWoQebeFBHFK8bHR
AOYmw2Ty3s8icbCMYplrcte0eh29gnz4CWWNmCl0u3FVibBCx5HJpJHu+32xjOWE
IF2dgP8V1W91KF0PNAODclkVD1MyM8zFOKYvMhekMJGOmkRyK9ljd0/TNU3xHeDv
aHTyvT8WWzEFgObhXXaA2nY38FL1bdG6Z9qM5QIDAQABAoIBAAk9J9brN60/9UmR
WrkRRa4l5tnjA/LMzUD/jOqfIEW4EK2fbD0894DSdlKQpIOrEYTRYt0bXo1Q4ute
kuF7YTbAU5ifyopR2Py0QlHSKasG3sUYCRB8ofOPMajt4+3nljKybVPojqgpIsCc
GdPXIArLH9LSlCVq1b5vPeDM4lmZWihFY+3a4uKOxv57cjX/pydwOVyN56QtyYP8
4fNGMR1w5jpF4wFtU0u3M3Myi1vYiH5aMy8a5pwVjNSENb8CX59Do+zj7v80kpJB
nITj99uTQ2jVnAh/lB2IN1fTgu1K0GN4ajFbYU09Kjr9KQC38zd7Q/kYZs8zGNk5
/EkLDwECgYEA9X17EtNDi+LPlISgcmOzRtzToZYaEdTAKyh2uMziHjN0sESkL/pv
FO1qUdK5oIWN2lcn9pieD+xrhq+w0r/HhkuhNviBHd2teKptbitJyl+iPT0YO+ib
B0DtMF3LaXMr0o5QZOzExxF1QWGPYwl1WC0Ezk9CtVhPACgCyxEraCkCgYEA05lQ
doWWMAePvqxVEAQ4ijuz4BnjBfwQNur6EezjJPVZK9PJ8tSLlWXzYPcUJAvomuik
BuXwenNGnLJaPI5SZGRUTG4wKxXjV34ISBTeY30WFvxPChsL2lm8bL9dDmhrEary
4t4KiaUOgppIwYiFGg2SWELC9e5UQRWFth0Wxl0CgYA1ufOgiBoFWGtDvs76mfVX
cebjO12TP3ObPmzVPwnRwEMufKdOVMnQ07DsHWlAx1nnSiHV50rYg055GKRjS1OY
gZ7T0Ak6BxT7DpmKffDVWJ7CNkfCfMLJEJ2Ycz6cYndZyomvvN3ID3sRBxABhcVn
udqOaGxaEeygRSFvXd+ZGQKBgEe2Zxm0DoF6npHtj+qcs5jNwRmLTHCjy88A9f2L
PjQxXqZG4eOFe0UHx2Muecn5qzyM6cJYvZaSaPUEUSbCyVOy2QsKMRL5GRJ26VGc
mP44z3q8ygDPx8WZsg1dEamnY9oaCLUwsXuS0AcdSNkmbo202ctF3RNCUZW5OJbO
5wAVAoGAXC1Na/71RLRgU2wP3Wupw9rn4sGjPDaZhVvi8NLnxr6/f06TCHeykbPy
sk6MH4JC5g+vJifW2WSrRfXqB7ye0A79Nn3TEJLesZIHy2UaP7lSIrtx8mVy0cvA
TG4BOCQ1mLs0NF7Ho1XhIl/gRIqqPta81gB86iFjKWYMfhhg5IQ=
-----END RSA PRIVATE KEY-----`

describe('authorizer', () => {
  it('should reject no auth token', () => {
    const authorizer = require('./authorizer').default

    return authorizer({
      methodArn: 'bar'
    })
      .then(({ message, error }) => {
        expect(message).toEqual('Unauthorized')
        expect(error).toEqual('No authorization token present')
      })
  })

  it('should reject an invalid header', () => {
    const authorizer = require('./authorizer').default

    return authorizer({
      authorizationToken: 'foo',
      methodArn: 'bar',
      cookieName: 'foo'
    })
      .then(({ message, error }) => {
        expect(message).toEqual('Unauthorized')
        expect(error).toEqual('Invalid Cookie Header')
      })
  })

  it('should reject an invalid jwt', () => {
    const authorizer = require('./authorizer').default

    return authorizer({
      authorizationToken: 'jwt=foo',
      methodArn: 'bar',
      cookieName: 'foo'
    })
      .then(({ message, error }) => {
        expect(message).toEqual('Unauthorized')
        expect(error).toEqual('Invalid token')
      })
  })

  it('should handle errors', done => {
    mock('./jwk', () => {
      return url => Promise.reject(new Error('cats'))
    })

    const authorizer = require('./authorizer').default

    return authorizer({
      authorizationToken: invalidKid,
      methodArn: 'bar',
      cookieName: 'foo'
    })
      .catch(({ message, error }) => {
        expect(message).toEqual('cats')
        done()
      })
  })

  it('should reject a token with invalid kids', () => {
    mock('./jwk', () => {
      return url => Promise.resolve(keys)
    })

    const authorizer = require('./authorizer').default

    return authorizer({
      authorizationToken: invalidKid,
      methodArn: 'bar',
      cookieName: 'foo'
    })
      .then(({ message, error }) => {
        expect(message).toEqual('Unauthorized')
        expect(error).toEqual('Invalid kid')
      })
  })

  it('should reject an invalid signature', () => {
    mock('./jwk', () => {
      return url => Promise.resolve(keys)
    })

    const authorizer = require('./authorizer').default

    return authorizer({
      authorizationToken: invalidSignature,
      methodArn: 'bar',
      cookieName: 'foo'
    })
      .then(({ message, error }) => {
        expect(message).toEqual('Unauthorized')
        expect(error.message).toEqual('invalid signature')
      })
  })

  it('should reject expired token', () => {
    mock('./jwk', () => {
      return url => Promise.resolve([
        publicKey
      ])
    })

    const aud = 'test'

    const now = new Date()
    const signed = require('jsonwebtoken').sign({
      iss: 'https://foo.bar.com',
      aud,
      iat: Math.floor(new Date(
        now.getFullYear() - 2,
        now.getMonth(),
        now.getDate()
      ).getTime() / 1000),
      exp: Math.floor(new Date(
        now.getFullYear() - 1,
        now.getMonth(),
        now.getDate()
      ).getTime() / 1000)
    }, privateKey, { algorithm: 'RS256', header: { kid: publicKey.kid } })

    const authorizer = require('./authorizer').default

    return authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      audience: aud,
      cookieName: 'foo'
    })
      .then(({ message, error }) => {
        expect(message).toEqual('Unauthorized')
        expect(error.message).toEqual('jwt expired')
      })
  })

  it('should reject token with wrong aud', () => {
    mock('./jwk', () => {
      return url => Promise.resolve([
        publicKey
      ])
    })

    const aud = 'test'

    const now = new Date()
    const signed = require('jsonwebtoken').sign({
      iss: 'https://foo.bar.com',
      aud,
      iat: Math.floor(new Date(
        now.getFullYear() - 2,
        now.getMonth(),
        now.getDate()
      ).getTime() / 1000),
      exp: Math.floor(new Date(
        now.getFullYear() + 1,
        now.getMonth(),
        now.getDate()
      ).getTime() / 1000)
    }, privateKey, { algorithm: 'RS256', header: { kid: publicKey.kid } })

    const authorizer = require('./authorizer').default

    return authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      audience: 'prod',
      cookieName: 'foo'
    })
      .then(({ message, error }) => {
        expect(message).toEqual('Unauthorized')
        expect(error.message).toEqual('jwt audience invalid. expected: prod')
      })
  })

  it('should reject token with wrong iss', () => {
    mock('./jwk', () => {
      return url => Promise.resolve([
        publicKey
      ])
    })

    const aud = 'test'

    const now = new Date()
    const signed = require('jsonwebtoken').sign({
      iss: 'https://foo.bar.com',
      aud,
      iat: Math.floor(new Date(
        now.getFullYear() - 2,
        now.getMonth(),
        now.getDate()
      ).getTime() / 1000),
      exp: Math.floor(new Date(
        now.getFullYear() + 1,
        now.getMonth(),
        now.getDate()
      ).getTime() / 1000)
    }, privateKey, { algorithm: 'RS256', header: { kid: publicKey.kid } })

    const authorizer = require('./authorizer').default

    return authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'bar',
      audience: aud,
      issuer: 'https://bar.foo.com',
      cookieName: 'foo'
    })
      .then(({ message, error }) => {
        expect(message).toEqual('Unauthorized')
        expect(error.message).toEqual('jwt issuer invalid. expected: https://bar.foo.com')
      })
  })

  it('should validate a valid token', () => {
    mock('./jwk', () => {
      return url => Promise.resolve([
        publicKey
      ])
    })

    const aud = 'test'

    const now = new Date()
    const signed = require('jsonwebtoken').sign({
      email: 'foo@bar.com',
      iss: 'https://foo.bar.com',
      aud,
      iat: Math.floor(new Date(
        now.getFullYear() - 2,
        now.getMonth(),
        now.getDate()
      ).getTime() / 1000),
      exp: Math.floor(new Date(
        now.getFullYear() + 1,
        now.getMonth(),
        now.getDate()
      ).getTime() / 1000)
    }, privateKey, { algorithm: 'RS256', header: { kid: publicKey.kid } })

    const authorizer = require('./authorizer').default

    return authorizer({
      authorizationToken: `foo=${signed}`,
      methodArn: 'arn:aws:execute-api:us-east-1:123456789012:qsxrty/foo/GET/api/service-agreements/',
      path: '/api/service-agreements',
      audience: aud,
      cookieName: 'foo'
    })
      .then(({ policy }) => {
        expect(policy).toBeDefined()
        expect(policy).toMatchObject({
          principalId: 'foo@bar.com',
          policyDocument: {
            Version: '2012-10-17',
            Statement: [{
              Action: 'execute-api:Invoke',
              Effect: 'Allow',
              Resource: [
                'arn:aws:execute-api:us-east-1:123456789012:qsxrty/foo/*/api/service-agreements',
                'arn:aws:execute-api:us-east-1:123456789012:qsxrty/foo/*/api/service-agreements/*'
              ]
            }]
          }
        })
      })
  })
})
