'use strict'

import axios from 'axios'
let jwks // 'cache' JWK in memory for the life of the lambda container

export default discoUrl => {
  if (jwks) {
    return Promise.resolve(jwks)
  }
  return axios.get(discoUrl)
    .then(response => axios.get(response.data.jwks_uri))
    .then(response => {
      jwks = response.data.keys
      return jwks
    })
}
