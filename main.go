package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jncmaguire/openapi-testing/internal/istio"
	"github.com/jncmaguire/openapi-testing/internal/openapi"
)

func main() {
	requirements, err := openapi.GetSecurityRequirements("./resources/openapi.json") // render braces in path?

	fmt.Println(requirements)

	if err != nil {
		panic(err)
	}

	rules, err := istio.GetAuthorizationRules(`./resources/authorizationpolicy.yaml`)

	if err != nil {
		panic(err)
	}

	fmt.Println(rules)

	ruleHasRequirement := make([]bool, len(rules))
	requirementHasRule := make([]bool, len(requirements))
	for i := range requirements {
		for j := range rules {
			if ruleRequirementMatch(rules[j], requirements[i]) {
				ruleHasRequirement[j] = true
				requirementHasRule[i] = true
				break
			}
		}
		if !requirementHasRule[i] {
			fmt.Println("missing policy for OpenAPI requirement", requirements[i].Path)
		}
	}

	for i := range rules {
		if !ruleHasRequirement[i] {
			fmt.Println("missing permission for policy", rules[i])
		}
	}
}

func ruleRequirementMatch(rule istio.Rule, requirement openapi.SecurityRequirement) bool {
	// first, match the To
	for _, to := range rule.To {
		// check that the method matches
		if !to.MethodAllowed(requirement.Method) {
			return false
		}

		// check that it matches at least 1 path
		for path, allowed := range to.Paths {
			// replace * with .*
			if !regexp.MustCompile(strings.Replace(path, `*`, `.*`, -1)).MatchString(requirement.Path) {
				continue
			}

			if !allowed { // check that it doesn't match a not Path
				return false
			}
		}
	}

	// next, match the When
	foundScopes := make(map[string]struct{})
	for _, when := range rule.When {
		for _, req := range requirement.Requirements[`petstore_auth`] { // hardcoding for simplicity
			if when.Values[req] { // add to found list if found
				foundScopes[req] = struct{}{}
			}
		}
	}

	return len(foundScopes) == len(requirement.Requirements[`petstore_auth`])
}
