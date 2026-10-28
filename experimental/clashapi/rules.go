package clashapi

import (
	"net/http"

	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func ruleRouter(router adapter.Router) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules(router))
	return r
}

type Rule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
}

func getRules(router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var rules []Rule
		consume := func(rawRules []adapter.Rule) {
			for _, rule := range rawRules {
				rules = append(rules, Rule{
					Type:    rule.Type(),
					Payload: rule.String(),
					Proxy:   rule.Action().String(),
				})
			}
		}
		if runtime, ok := router.(interface{ WithRuntimeRules(func([]adapter.Rule)) }); ok {
			runtime.WithRuntimeRules(consume)
		} else {
			consume(router.Rules())
		}
		render.JSON(w, r, render.M{
			"rules": rules,
		})
	}
}
