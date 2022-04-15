package openapi

import (
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
)

type SecurityRequirement struct {
	Path         string
	Method       string
	Requirements map[string][]string
}

func GetSecurityRequirements(path string) ([]SecurityRequirement, error) {
	docs, err := getDocs(path)
	if err != nil {
		return nil, err
	}

	requirements := make([]SecurityRequirement, 0, len(docs.Paths))
	for name, path := range docs.Paths {
		for method, op := range map[string]*openapi3.Operation{
			http.MethodConnect: path.Connect,
			http.MethodDelete:  path.Delete,
			http.MethodGet:     path.Get,
			http.MethodHead:    path.Head,
			http.MethodOptions: path.Options,
			http.MethodPatch:   path.Patch,
			http.MethodPost:    path.Post,
			http.MethodPut:     path.Put,
			http.MethodTrace:   path.Trace,
		} {
			if op == nil {
				continue
			}

			if op.Security == nil {
				continue
			}

			requirements = append(requirements, SecurityRequirement{ // TODO: may need to render braces
				Path:         name,
				Method:       method,
				Requirements: getRequirements(*op.Security),
			})
		}

	}

	return requirements, nil
}

func getDocs(path string) (*openapi3.T, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true

	docs, err := loader.LoadFromFile(path)
	if err != nil {
		return nil, err
	}

	if err = docs.Validate(loader.Context); err != nil {
		return nil, err
	}

	return docs, nil
}

func getRequirements(security openapi3.SecurityRequirements) map[string][]string {
	requirements := make(map[string][]string)
	for _, requirement := range security {
		for key, values := range requirement {
			requirements[key] = append(requirements[key], values...)
		}
	}
	return requirements
}
