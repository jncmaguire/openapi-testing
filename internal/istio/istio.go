package istio

import (
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"
	istioPB "istio.io/api/security/v1beta1"
	istioModel "istio.io/istio/pilot/pkg/model"
)

type Rule struct {
	When []Condition
	To   []Operation
}

type Condition struct {
	Key    string
	Values map[string]bool
}

type Operation struct {
	Methods map[string]bool
	Paths   map[string]bool
}

func (op *Operation) MethodAllowed(method string) bool {
	return op.Methods[method]
}

func GetAuthorizationRules(path string) ([]Rule, error) {
	body, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	policy, err := getAuthorizationPolicy(body)

	rules := make([]Rule, 0, len(policy.GetRules()))
	for _, specRule := range policy.GetRules() {
		if specRule == nil {
			continue
		}

		var r Rule

		r.When = make([]Condition, 0, len(specRule.When))
		for _, when := range specRule.When {
			if when == nil {
				continue
			}

			r.When = append(r.When, Condition{
				Key:    when.Key,
				Values: buildNegationMap(when.Values, when.NotValues),
			})

		}

		r.To = make([]Operation, 0, len(specRule.To))
		for _, to := range specRule.To {
			if to == nil {
				continue
			}

			r.To = append(r.To, Operation{
				Methods: buildNegationMap(to.Operation.Methods, to.Operation.NotMethods),
				Paths:   buildNegationMap(to.Operation.Paths, to.Operation.NotPaths),
			})
		}

		rules = append(rules, r)
	}

	return rules, nil
}

func buildNegationMap(positive []string, negative []string) map[string]bool {
	m := make(map[string]bool)

	for _, v := range positive {
		m[v] = true
	}

	for _, v := range negative {
		m[v] = false
	}
	return m
}

func getAuthorizationPolicy(input []byte) (*istioPB.AuthorizationPolicy, error) {
	body := replaceEnum(input) // required for use with YAML reader

	var policy istioModel.AuthorizationPolicy
	if err := yaml.Unmarshal(body, &policy); err != nil {
		return nil, err
	}

	if policy.Spec == nil {
		return nil, errors.New("no spec found")
	}

	return policy.Spec, nil
}

func replaceEnum(input []byte) []byte {
	actions := make([]string, 0, len(istioPB.AuthorizationPolicy_Action_value))
	for k := range istioPB.AuthorizationPolicy_Action_value {
		actions = append(actions, k)
	}

	return regexp.MustCompile(fmt.Sprintf(`action\:\s*(%s)`, strings.Join(actions, `|`))).ReplaceAllFunc(input, func(match []byte) []byte {
		w := string(match)
		for k, v := range istioPB.AuthorizationPolicy_Action_value {
			w = strings.Replace(w, k, fmt.Sprint(v), -1)
		}
		return []byte(w)
	})
}
