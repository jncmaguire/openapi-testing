# OpenAPI Testing

This is a repo of attempts at using OpenAPI documentation to automatically validate and test certain aspects of a service.

This service is not to be considered a full-fledged package, but to serve as a reference for how such tasks might be done.

## Features

### Istio

This code supports a basic first-pass at using an Istio Authorization Policy in order to test the correctness of a OpenAPI spec and vice versa.

The idea is to validate that every authorization policy someone writes is successfully documented in an OpenAPI spec, and that everything documented in an OpenAPI spec is supported by a policy.

## Notes

* The authorization policy was written based off of what was actually in the [Petstore example](https://petstore3.swagger.io/api/v3/openapi.json) (and I am not an expert).
* Istio supports [limited wildcarding only](https://stackoverflow.com/questions/65706467/istio-authorizationpolicy-with-wildcard). This means some security schemes could not be fully translated to istio.

## Other Areas of Exploration

* Making the code more generic / extensible for different types of auth policy rules and different types of security schemes
* Automated tests using security schemes
* Automated tests using examples
