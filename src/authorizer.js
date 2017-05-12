import j from 'pem-jwk'
import { verify, decode } from 'jsonwebtoken'
import { parseCookieHeader } from 'strict-cookie-parser'
import getJwks from './jwk'

export default ({
  authorizationToken,
  methodArn,
  path,
  audience,
  discoveryUrl,
  issuer,
  cookieName
}) => {
  if (!authorizationToken) {
    return Promise.resolve({ message: 'Unauthorized', error: 'No authorization token present' })
  }

  const cookies = parseCookieHeader(authorizationToken)

  if (!cookies) {
    return Promise.resolve({ message: 'Unauthorized', error: 'Invalid Cookie Header' })
  }

  const token = cookies.get(cookieName)

  const unverified = decode(token, { complete: true })
  if (!unverified || !unverified.header || !unverified.header.kid) {
    return Promise.resolve({ message: 'Unauthorized', error: 'Invalid token' })
  }

  return getJwks(discoveryUrl)
    .then(jwks => {
      const jwk = jwks.find(i => i.kid === unverified.header.kid)
      if (!jwk) {
        return { message: 'Unauthorized', error: 'Invalid kid' }
      }

      const pem = j.jwk2pem(jwk)
      let decoded
      try {
        decoded = verify(token, pem, { algorithm: 'RS256', audience, issuer })
      } catch (error) {
        return { message: 'Unauthorized', error }
      }

      // see http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html
      const resourceParts = methodArn.split('/')
      const resource = `${resourceParts[0]}/${resourceParts[1]}/*${path}`
      return {
        policy: {
          principalId: decoded.email,
          policyDocument: {
            Version: '2012-10-17',
            Statement: [{
              Action: 'execute-api:Invoke',
              Effect: 'Allow',
              Resource: [resource, `${resource}/*`]
            }]
          }
        }
      }
    })
}
