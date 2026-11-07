package core

import "testing"

func TestConditions(t *testing.T) {
	env := map[string]any{"request": map[string]any{"amount": 500, "currency": "ETB", "branch": "b1", "urgent": true}}
	for expr, want := range map[string]bool{
		`request.amount <= 1000 && request.currency == "ETB"`: true,
		`request.amount > 1000`:                               false,
		`request.branch in ["b1", "b2"]`:                      true,
		`!(request.branch in ["b3"]) && request.urgent`:       true,
		`request.currency != 'ETB' || request.amount == 500`:  true,
		`request.amount >= 500.0 && (request.urgent == true)`: true,
		`request.branch == "b1" && request.amount < 100`:      false,
	} {
		got, err := EvalCondition(expr, env)
		if err != nil || got != want {
			t.Errorf("%s: got %v (%v), want %v", expr, got, err, want)
		}
	}
	// Missing values and type mixes fail, never pass.
	for _, expr := range []string{`request.missing == 1`, `request.amount == "500"`, `request.amount`, `request.amount <`, `foo(1)`} {
		if ok, err := EvalCondition(expr, env); ok || err == nil {
			t.Errorf("%s should fail, got %v %v", expr, ok, err)
		}
	}
	if err := CheckCondition(`request.amount <= 10 && request.x in ["a"]`); err != nil {
		t.Error(err)
	}
	if err := CheckCondition(`request.amount <= `); err == nil {
		t.Error("an incomplete condition parsed")
	}
}
