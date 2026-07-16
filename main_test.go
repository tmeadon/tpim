package main

import (
	"errors"
	"testing"
	"time"
)

func TestGetGUID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "/subscriptions/123-abc/providers/Microsoft.Authorization/roleDefinitions/fe2a5f78-fb8d-4785-ad6c-d2320b925b4b",
			expected: "fe2a5f78-fb8d-4785-ad6c-d2320b925b4b",
		},
		{
			input:    "abc",
			expected: "abc",
		},
		{
			input:    "   trimmed-guid   ",
			expected: "trimmed-guid",
		},
		{
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		result := getGUID(tt.input)
		if result != tt.expected {
			t.Errorf("getGUID(%q) = %q; expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestNormalizeScope(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "/subscriptions/123/ ",
			expected: "/subscriptions/123",
		},
		{
			input:    " /SUBSCRIPTIONS/ABC/providers ",
			expected: "/subscriptions/abc/providers",
		},
		{
			input:    "/",
			expected: "/",
		},
		{
			input:    "",
			expected: "/",
		},
	}

	for _, tt := range tests {
		result := normalizeScope(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeScope(%q) = %q; expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestCleanErrorMessage(t *testing.T) {
	tests := []struct {
		input    error
		expected string
	}{
		{
			input:    errors.New("failed to run: exit status 1. Stderr: {\"error\":{\"code\":\"PermissionScopeNotGranted\",\"message\":\"Authorization failed due to missing permission scope.\"}}"),
			expected: "Authorization failed due to missing permission scope.",
		},
		{
			input:    errors.New("failed to run: exit status 1. Stderr: some plain text error message"),
			expected: "some plain text error message",
		},
		{
			input:    errors.New("some raw backend issue"),
			expected: "some raw backend issue",
		},
	}

	for _, tt := range tests {
		result := cleanErrorMessage(tt.input)
		if result.Error() != tt.expected {
			t.Errorf("cleanErrorMessage(%v) = %q; expected %q", tt.input, result.Error(), tt.expected)
		}
	}
}

func TestGetRemainingStr(t *testing.T) {
	m := model{}

	// Test zero time
	if res := m.getRemainingStr(time.Time{}); res != "" {
		t.Errorf("expected empty string for zero time, got %q", res)
	}

	// Test expired time
	if res := m.getRemainingStr(time.Now().Add(-1 * time.Minute)); res != "Expired" {
		t.Errorf("expected 'Expired' for past time, got %q", res)
	}

	// Test active remaining string (add a 2s safety buffer to avoid timing races in tests)
	future := time.Now().Add(2*time.Hour + 15*time.Minute + 30*time.Second)
	res := m.getRemainingStr(future)
	expectedPrefix := "02h 15m"
	if !testing.Short() {
		// Just check that it starts with the correct hours and minutes to avoid flaky second comparisons
		if len(res) < 8 || res[:7] != expectedPrefix {
			t.Errorf("getRemainingStr(%v) = %q; expected prefix %q", future, res, expectedPrefix)
		}
	}
}
