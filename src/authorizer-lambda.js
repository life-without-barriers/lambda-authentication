import authorizer from './authorizer'

export default ({ path, logger, audience, discoveryUrl, issuer, cookieName }) => ({ authorizationToken, methodArn }, context, callback) => {
  return authorizer({
    authorizationToken,
    methodArn,
    path,
    audience,
    discoveryUrl,
    issuer,
    cookieName
  })
    .then(({ policy, error, message }) => {
      if (policy) {
        logger && logger.info(policy, 'Received policy')
        return callback(null, policy)
      }
      logger && logger.error(error, message)
      callback(message)
    })
    .catch(error => {
      logger&& logger.error(error)
      callback(error.message)
    })
}
