import authorizer from './authorizer'

export default ({ path, logger, audience, secret, issuer, cookieName }) => ({ authorizationToken, methodArn }, context, callback) => {
  const { policy, error, message } = authorizer({
    authorizationToken,
    methodArn,
    path,
    audience,
    secret,
    issuer,
    cookieName
  })
  if (policy) {
    logger && logger.info(policy, 'Received policy')
    return callback(null, policy)
  }
  logger && logger.error(error, message)
  callback(message)
}
