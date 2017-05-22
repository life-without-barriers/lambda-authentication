import { verify } from 'jsonwebtoken'
import { parseCookieHeader } from 'strict-cookie-parser'
import policy from './policy'

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
    return { message: 'Unauthorized', error: 'No authorization token present' }
  }

  const cookies = parseCookieHeader(authorizationToken)
  if (!cookies) {
    return { message: 'Unauthorized', error: 'Invalid Cookie Header' }
  }
  const token = cookies.get(cookieName)
  if (!token) {
    return { message: 'Unauthorized', error: `${cookieName} not found in cookies` }
  }

  let decoded
  try {
    decoded = verify(token, secret, { algorithm: 'HS256', audience, issuer })
  } catch (error) {
    return { message: 'Unauthorized', error }
  }

  if (!decoded.sub) {
    return { message: 'Unauthorized', error: 'sub is a required claim' }
  }
  return policy(path, methodArn, decoded.sub)
}
