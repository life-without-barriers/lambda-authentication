const { resetModules, mock } = jest
const UnauthorizedError = require('./unauthorized-error').default

beforeEach(() => {
  resetModules()
})

describe('lambda authorizer', () => {
  it('should return a policy when provided', done => {
    mock('./authorizer', () => {
      return () => ({ foo: 'bar' })
    })

    const lambda = require('./authorizer-lambda').default
    lambda({})({}, null, (err, policy) => {
      expect(err).toBeNull()
      expect(policy).toBeDefined()
      expect(policy).toMatchObject({
        foo: 'bar'
      })
      done()
    })
  })

  it('should return Unauthorized when auth failed', done => {
    const error = new UnauthorizedError('Invalid Cookie Header')
    mock('./authorizer', () => {
      return () => { throw error }
    })

    const lambda = require('./authorizer-lambda').default
    lambda({})({}, null, error => {
      expect(error).toBeDefined()
      expect(error).toEqual(error)
      done()
    })
  })

  it('should return unknown errors', done => {
    const error = new Error('cats')
    mock('./authorizer', () => {
      return () => { throw error }
    })

    const lambda = require('./authorizer-lambda').default
    lambda({})({}, null, error => {
      expect(error).toBeDefined()
      expect(error).toEqual(error)
      done()
    })
  })
})
