const { resetModules, mock } = jest

beforeEach(() => {
  resetModules()
})

describe('lambda authorizer', () => {
  it('should return a policy when provided', done => {
    mock('./authorizer', () => {
      return () => ({ policy: { foo: 'bar' } })
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
    mock('./authorizer', () => {
      return () => ({ message: 'Unauthorized', error: 'Invalid Cookie Header' })
    })

    const lambda = require('./authorizer-lambda').default
    lambda({})({}, null, error => {
      expect(error).toBeDefined()
      expect(error).toEqual('Unauthorized')
      done()
    })
  })

  it('should return unknown errors', done => {
    mock('./authorizer', () => {
      return () => (new Error('cats'))
    })

    const lambda = require('./authorizer-lambda').default
    lambda({})({}, null, error => {
      expect(error).toBeDefined()
      expect(error).toEqual('cats')
      done()
    })
  })
})
