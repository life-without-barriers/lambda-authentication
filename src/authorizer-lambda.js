import authorizer from './authorizer'

export default ({ path, logger, audience, secret, issuer, cookieName }) => ({ authorizationToken, methodArn }, context, callback) => {
  try {
    const policy = authorizer({
      authorizationToken,
      methodArn,
      path,
      audience,
      secret,
      issuer,
      cookieName
    })
    logger && logger.info(policy, 'Received policy')
    callback(null, policy)
  } catch (error) {
    logger && logger.error(error)
    callback(error)
  }
}
