// see http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html

export default (path, methodArn, principalId) => {
  const resourceParts = methodArn.split('/')
  const resource = `${resourceParts[0]}/${resourceParts[1]}/*${path}`
  return {
    principalId: principalId,
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
