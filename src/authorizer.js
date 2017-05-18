import { verify } from 'jsonwebtoken'
import { parseCookieHeader } from 'strict-cookie-parser'
import policy from './policy'
import UnauthorizedError from './unauthorized-error'

export default ({
  authorizationToken,
  methodArn,
  path,
  audience,
  secret,
  issuer,
  cookieName
}) => {
  if (!authorizationToken) {
    throw new UnauthorizedError('No authorization token present')
  }

  const cookies = parseCookieHeader(authorizationToken)
  if (!cookies) {
    throw new UnauthorizedError('Invalid Cookie Header')
  }

  const token = cookies.get(cookieName)
  if (!token) {
    throw new UnauthorizedError(`${cookieName} not found in cookies`)
  }

  const decoded = verify(token, secret, { algorithm: 'HS256', audience, issuer })
  if (!decoded.sub) {
    throw new UnauthorizedError('sub is a required claim')
  }

  return policy(path, methodArn, decoded.sub)
}
