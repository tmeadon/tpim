package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

var globalProgram *tea.Program

// PimRole represents a PIM role definition and its status
type PimRole struct {
	Type             string    // "Azure Resource" or "Directory Role"
	RoleName         string    // e.g. "Owner"
	RoleDefinitionID string    // Full ID path of the role definition
	ScopeName        string    // e.g. "GLNG - Sandbox"
	ScopeID          string    // Scope URI path
	ScopeType        string    // e.g. "subscription", "resourcegroup", "managementgroup", "directory"
	ScheduleName     string    // GUID name of the eligibility schedule
	Status           string    // "Eligible", "Active", "Assigned"
	ExpiresDT        time.Time // Expiration time for Active PIM assignments
}

// -------------------------------------------------------------
// JSON API response structs
// -------------------------------------------------------------

type EligibleSchedulesResponse struct {
	Value []EligibleSchedule `json:"value"`
}

type EligibleSchedule struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"` // GUID
	Properties EligibleScheduleProps `json:"properties"`
}

type EligibleScheduleProps struct {
	RoleDefinitionID   string             `json:"roleDefinitionId"`
	Scope              string             `json:"scope"`
	ExpandedProperties ExpandedProperties `json:"expandedProperties"`
}

type ExpandedProperties struct {
	RoleDefinition RoleDef `json:"roleDefinition"`
	Scope          Scope   `json:"scope"`
}

type RoleDef struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type Scope struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Type        string `json:"type"`
}

type ActiveInstancesResponse struct {
	Value []ActiveInstance `json:"value"`
}

type ActiveInstance struct {
	Properties ActiveInstanceProps `json:"properties"`
}

type ActiveInstanceProps struct {
	AssignmentType            string             `json:"assignmentType"` // "Activated", "Assigned"
	EndDateTime               string             `json:"endDateTime"`
	RoleDefinitionID          string             `json:"roleDefinitionId"`
	Scope                     string             `json:"scope"`
	RoleEligibilityScheduleID string             `json:"roleEligibilityScheduleId"`
	ExpandedProperties        ExpandedProperties `json:"expandedProperties"`
}

type GraphSchedulesResponse struct {
	Value []GraphSchedule `json:"value"`
}

type GraphSchedule struct {
	ID               string       `json:"id"`
	RoleDefinitionID string       `json:"roleDefinitionId"`
	DirectoryScopeID string       `json:"directoryScopeId"`
	AssignmentType   string       `json:"assignmentType"` // For instances
	EndDateTime      string       `json:"endDateTime"`     // For instances
	RoleDefinition   GraphRoleDef `json:"roleDefinition"`
}

type GraphRoleDef struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// -------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------

type TokenCache struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type deviceCodeMsg struct {
	Message         string
	UserCode        string
	VerificationURL string
}

func getGraphToken() (string, error) {
	cachePath := "/home/tom/.gemini/antigravity-cli/pim_token.json"
	
	// Try reading cache
	if data, err := os.ReadFile(cachePath); err == nil {
		var cache TokenCache
		if json.Unmarshal(data, &cache) == nil {
			// Check if token is still valid (with 5-minute safety margin)
			if time.Now().Add(5 * time.Minute).Before(cache.ExpiresAt) {
				return cache.Token, nil
			}
		}
	}

	// Token not cached or expired, perform device code login
	cred, err := azidentity.NewDeviceCodeCredential(&azidentity.DeviceCodeCredentialOptions{
		ClientID: "14d82eec-204b-4c2f-b7e8-296a70dab67e", // Microsoft Graph Command Line Tools
		UserPrompt: func(ctx context.Context, message azidentity.DeviceCodeMessage) error {
			if globalProgram != nil {
				globalProgram.Send(deviceCodeMsg{
					Message:         message.Message,
					UserCode:        message.UserCode,
					VerificationURL: message.VerificationURL,
				})
			}
			return nil
		},
	})
	if err != nil {
		return "", err
	}

	tokenOpts := policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
	}
	token, err := cred.GetToken(context.Background(), tokenOpts)
	if err != nil {
		return "", err
	}

	// Write to cache
	cache := TokenCache{
		Token:     token.Token,
		ExpiresAt: token.ExpiresOn,
	}
	if cacheData, err := json.Marshal(cache); err == nil {
		_ = os.WriteFile(cachePath, cacheData, 0600)
	}

	return token.Token, nil
}

func graphRequest(method, urlStr, token string, body []byte) (string, error) {
	var reqBody io.Reader
	if len(body) > 0 {
		reqBody = bytes.NewBuffer(body)
	}
	
	req, err := http.NewRequest(method, urlStr, reqBody)
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	
	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	
	if res.StatusCode >= 400 {
		var parseErr struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(respBody, &parseErr) == nil && parseErr.Error.Message != "" {
			return "", errors.New(parseErr.Error.Message)
		}
		return "", fmt.Errorf("HTTP %s: %s", res.Status, string(respBody))
	}
	
	return string(respBody), nil
}

func runAzCmd(args ...string) (string, error) {
	cmd := exec.Command("az", args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to run: %w. Stderr: %s", err, stderrBuf.String())
	}
	return stdoutBuf.String(), nil
}

func getGUID(idPath string) string {
	idPath = strings.TrimSpace(idPath)
	parts := strings.Split(idPath, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func normalizeScope(scope string) string {
	scope = strings.ToLower(strings.TrimSpace(scope))
	scope = strings.TrimSuffix(scope, "/")
	if scope == "" {
		return "/"
	}
	return scope
}

func cleanErrorMessage(err error) error {
	errStr := err.Error()
	start := strings.Index(errStr, "{")
	end := strings.LastIndex(errStr, "}")
	if start != -1 && end != -1 && end > start {
		jsonStr := errStr[start : end+1]
		var parseErr struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(jsonStr), &parseErr) == nil && parseErr.Error.Message != "" {
			return errors.New(parseErr.Error.Message)
		}
	}
	clean := strings.TrimPrefix(errStr, "failed to run: exit status 1. Stderr: ")
	clean = strings.TrimPrefix(clean, "failed to run: exit status 1. ")
	return errors.New(clean)
}

func newUUID() (string, error) {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		return "", err
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

func padTrunc(s string, width int) string {
	w := runewidth.StringWidth(s)
	if w > width {
		return runewidth.Truncate(s, width, "...")
	}
	return s + strings.Repeat(" ", width-w)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// -------------------------------------------------------------
// Bubble tea message structures
// -------------------------------------------------------------

type initInfoMsg struct {
	UserID     string
	UserName   string
	TenantName string
	TenantID   string
	Err        error
}

type fetchRolesMsg struct {
	Roles    []PimRole
	EntraErr error
	Err      error
}

type activateRoleResultMsg struct {
	Err error
}

type deactivateRoleResultMsg struct {
	Err error
}

type extendRoleResultMsg struct {
	Err error
}

type tickMsg time.Time

// -------------------------------------------------------------
// Styles (Tokyo Night palette inspired)
// -------------------------------------------------------------

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#ffffff")).
			Background(lipgloss.Color("#414868")).
			Padding(0, 1)

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#9ece6a")).
			Background(lipgloss.Color("#414868"))

	selectedRowStyle = lipgloss.NewStyle().
				Bold(true).
				Background(lipgloss.Color("#2f334d")).
				Foreground(lipgloss.Color("#ffffff"))

	normalRowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#a9b1d6"))

	activeStatusStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#9ece6a")) // Green

	eligibleStatusStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#e0af68")) // Yellow/Orange

	assignedStatusStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#73daca")) // Teal/Cyan

	modalStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#7aa2f7")).
			Padding(1, 2).
			Width(62)

	errorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#f7768e"))
)

// -------------------------------------------------------------
// Command builders
// -------------------------------------------------------------

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func initInfoCmd() tea.Msg {
	stdout, err := runAzCmd("account", "show")
	if err != nil {
		return initInfoMsg{Err: fmt.Errorf("Azure CLI not authenticated. Please run 'az login'")}
	}

	var acct struct {
		User struct {
			Name string `json:"name"`
		} `json:"user"`
		TenantDisplayName   string `json:"tenantDisplayName"`
		TenantDefaultDomain string `json:"tenantDefaultDomain"`
		TenantID            string `json:"tenantId"`
	}
	if err := json.Unmarshal([]byte(stdout), &acct); err != nil {
		return initInfoMsg{Err: fmt.Errorf("failed to parse account details: %w", err)}
	}

	tenantName := acct.TenantDisplayName
	if tenantName == "" {
		tenantName = acct.TenantDefaultDomain
	}

	stdoutID, err := runAzCmd("ad", "signed-in-user", "show", "--query", "id", "-o", "tsv")
	if err != nil {
		return initInfoMsg{Err: fmt.Errorf("failed to retrieve user ID: %w", err)}
	}
	userID := strings.TrimSpace(stdoutID)

	return initInfoMsg{
		UserID:     userID,
		UserName:   acct.User.Name,
		TenantName: tenantName,
		TenantID:   acct.TenantID,
	}
}

func fetchRolesCmd(userID string) tea.Cmd {
	return func() tea.Msg {
		rolesMap := make(map[string]PimRole)

		// --- A. Azure Resource PIM Roles ---
		eligibleOut, err := runAzCmd(
			"rest", "--method", "get",
			"--uri", "https://management.azure.com/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01&$filter=asTarget()",
		)
		if err == nil {
			var eligibleResp EligibleSchedulesResponse
			if err := json.Unmarshal([]byte(eligibleOut), &eligibleResp); err == nil {
				for _, item := range eligibleResp.Value {
					roleDefGUID := getGUID(item.Properties.RoleDefinitionID)
					scope := normalizeScope(item.Properties.Scope)

					key := roleDefGUID + "|" + scope
					rolesMap[key] = PimRole{
						Type:             "Azure Resource",
						RoleName:         item.Properties.ExpandedProperties.RoleDefinition.DisplayName,
						RoleDefinitionID: item.Properties.RoleDefinitionID,
						ScopeName:        item.Properties.ExpandedProperties.Scope.DisplayName,
						ScopeID:          item.Properties.Scope,
						ScopeType:        item.Properties.ExpandedProperties.Scope.Type,
						ScheduleName:     item.Name,
						Status:           "Eligible",
					}
				}
			}
		}

		activeOut, err := runAzCmd(
			"rest", "--method", "get",
			"--uri", "https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01&$filter=asTarget()",
		)
		if err == nil {
			var activeResp ActiveInstancesResponse
			if err := json.Unmarshal([]byte(activeOut), &activeResp); err == nil {
				for _, item := range activeResp.Value {
					roleDefGUID := getGUID(item.Properties.RoleDefinitionID)
					scope := normalizeScope(item.Properties.Scope)

					key := roleDefGUID + "|" + scope

					var endDT time.Time
					if item.Properties.EndDateTime != "" {
						if parsed, err := time.Parse(time.RFC3339, item.Properties.EndDateTime); err == nil {
							endDT = parsed
						} else if parsed, err := time.Parse("2006-01-02T15:04:05.999999999Z", item.Properties.EndDateTime); err == nil {
							endDT = parsed
						}
					}

					if existing, found := rolesMap[key]; found {
						if item.Properties.AssignmentType == "Activated" {
							existing.Status = "Active"
							existing.ExpiresDT = endDT
							if existing.ScheduleName == "" {
								existing.ScheduleName = getGUID(item.Properties.RoleEligibilityScheduleID)
							}
							rolesMap[key] = existing
						}
					} else {
						roleName := item.Properties.ExpandedProperties.RoleDefinition.DisplayName
						if roleName == "" {
							roleName = "Unknown Role"
						}
						scopeName := item.Properties.ExpandedProperties.Scope.DisplayName
						if scopeName == "" {
							scopeName = "/"
						}
						status := "Active"
						if item.Properties.AssignmentType == "Assigned" {
							status = "Assigned"
						}
						rolesMap[key] = PimRole{
							Type:             "Azure Resource",
							RoleName:         roleName,
							RoleDefinitionID: item.Properties.RoleDefinitionID,
							ScopeName:        scopeName,
							ScopeID:          item.Properties.Scope,
							ScopeType:        item.Properties.ExpandedProperties.Scope.Type,
							ScheduleName:     getGUID(item.Properties.RoleEligibilityScheduleID),
							Status:           status,
							ExpiresDT:        endDT,
						}
					}
				}
			}
		}

		// --- B. Entra ID / Directory PIM Roles ---
		var entraErr error
		graphToken, err := getGraphToken()
		if err != nil {
			entraErr = fmt.Errorf("Graph auth failed: %w", err)
		} else {
			urlStr := fmt.Sprintf("https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$filter=principalId%%20eq%%20'%s'&$expand=roleDefinition", userID)
			entraEligibleOut, err := graphRequest("GET", urlStr, graphToken, nil)
			if err != nil {
				entraErr = err
			} else {
				var graphEligible GraphSchedulesResponse
				if err := json.Unmarshal([]byte(entraEligibleOut), &graphEligible); err == nil {
					for _, item := range graphEligible.Value {
						key := item.RoleDefinitionID + "|/"
						rolesMap[key] = PimRole{
							Type:             "Directory Role",
							RoleName:         item.RoleDefinition.DisplayName,
							RoleDefinitionID: item.RoleDefinitionID,
							ScopeName:        "Tenant Directory",
							ScopeID:          "/",
							ScopeType:        "directory",
							ScheduleName:     item.ID,
							Status:           "Eligible",
						}
					}
				} else {
					entraErr = err
				}
			}

			if entraErr == nil {
				urlStrAct := fmt.Sprintf("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$filter=principalId%%20eq%%20'%s'&$expand=roleDefinition", userID)
				entraActiveOut, err := graphRequest("GET", urlStrAct, graphToken, nil)
				if err != nil {
					entraErr = err
				} else {
					var graphActive GraphSchedulesResponse
					if err := json.Unmarshal([]byte(entraActiveOut), &graphActive); err == nil {
						for _, item := range graphActive.Value {
							key := item.RoleDefinitionID + "|/"

							var endDT time.Time
							if item.EndDateTime != "" {
								if parsed, err := time.Parse(time.RFC3339, item.EndDateTime); err == nil {
									endDT = parsed
								}
							}

							if existing, found := rolesMap[key]; found {
								if item.AssignmentType == "Activated" {
									existing.Status = "Active"
									existing.ExpiresDT = endDT
									rolesMap[key] = existing
								}
							} else {
								status := "Active"
								if item.AssignmentType == "Assigned" {
									status = "Assigned"
								}
								rolesMap[key] = PimRole{
									Type:             "Directory Role",
									RoleName:         item.RoleDefinition.DisplayName,
									RoleDefinitionID: item.RoleDefinitionID,
									ScopeName:        "Tenant Directory",
									ScopeID:          "/",
									ScopeType:        "directory",
									Status:           status,
									ExpiresDT:        endDT,
								}
							}
						}
					} else {
						entraErr = err
					}
				}
			}
		}

		var roles []PimRole
		for _, r := range rolesMap {
			roles = append(roles, r)
		}

		sort.Slice(roles, func(i, j int) bool {
			statusOrder := map[string]int{"Active": 0, "Eligible": 1, "Assigned": 2}
			oi := statusOrder[roles[i].Status]
			oj := statusOrder[roles[j].Status]
			if oi != oj {
				return oi < oj
			}
			if roles[i].RoleName != roles[j].RoleName {
				return strings.ToLower(roles[i].RoleName) < strings.ToLower(roles[j].RoleName)
			}
			return strings.ToLower(roles[i].ScopeName) < strings.ToLower(roles[j].ScopeName)
		})

		return fetchRolesMsg{Roles: roles, EntraErr: entraErr}
	}
}

func activateRoleCmd(userID string, role PimRole, justification string, durationHours int) tea.Cmd {
	return func() tea.Msg {
		durationStr := fmt.Sprintf("PT%dH", durationHours)

		if role.Type == "Azure Resource" {
			reqGUID, err := newUUID()
			if err != nil {
				return activateRoleResultMsg{Err: err}
			}

			body := map[string]interface{}{
				"properties": map[string]interface{}{
					"principalId":                     userID,
					"roleDefinitionId":                role.RoleDefinitionID,
					"requestType":                     "SelfActivate",
					"linkedRoleEligibilityScheduleId": role.ScheduleName,
					"justification":                  justification,
					"scheduleInfo": map[string]interface{}{
						"startDateTime": nil,
						"expiration": map[string]interface{}{
							"type":     "AfterDuration",
							"duration": durationStr,
						},
					},
				},
			}

			bodyJSON, err := json.Marshal(body)
			if err != nil {
				return activateRoleResultMsg{Err: err}
			}

			scope := role.ScopeID
			scope = strings.TrimSuffix(scope, "/")

			uri := fmt.Sprintf("https://management.azure.com%s/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/%s?api-version=2020-10-01", scope, reqGUID)

			_, err = runAzCmd("rest", "--method", "put", "--uri", uri, "--body", string(bodyJSON))
			if err != nil {
				return activateRoleResultMsg{Err: cleanErrorMessage(err)}
			}

		} else if role.Type == "Directory Role" {
			graphToken, err := getGraphToken()
			if err != nil {
				return activateRoleResultMsg{Err: err}
			}

			body := map[string]interface{}{
				"action":           "selfActivate",
				"principalId":      userID,
				"roleDefinitionId": role.RoleDefinitionID,
				"directoryScopeId": role.ScopeID,
				"justification":    justification,
				"scheduleInfo": map[string]interface{}{
					"startDateTime": nil,
					"expiration": map[string]interface{}{
						"type":     "afterDuration",
						"duration": durationStr,
					},
				},
			}

			bodyJSON, err := json.Marshal(body)
			if err != nil {
				return activateRoleResultMsg{Err: err}
			}

			uri := "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
			_, err = graphRequest("POST", uri, graphToken, bodyJSON)
			if err != nil {
				return activateRoleResultMsg{Err: err}
			}
		}

		return activateRoleResultMsg{}
	}
}

func deactivateRoleCmd(userID string, role PimRole) tea.Cmd {
	return func() tea.Msg {
		if role.Type == "Azure Resource" {
			reqGUID, err := newUUID()
			if err != nil {
				return deactivateRoleResultMsg{Err: err}
			}

			body := map[string]interface{}{
				"properties": map[string]interface{}{
					"roleDefinitionId":                role.RoleDefinitionID,
					"principalId":                     userID,
					"scope":                           role.ScopeID,
					"action":                          "SelfDeactivate",
					"linkedRoleEligibilityScheduleId": role.ScheduleName,
				},
			}

			bodyJSON, err := json.Marshal(body)
			if err != nil {
				return deactivateRoleResultMsg{Err: err}
			}

			uri := fmt.Sprintf("https://management.azure.com%s/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/%s?api-version=2020-10-01", role.ScopeID, reqGUID)

			_, err = runAzCmd("rest", "--method", "put", "--url", uri, "--body", string(bodyJSON))
			if err != nil {
				return deactivateRoleResultMsg{Err: cleanErrorMessage(err)}
			}

		} else if role.Type == "Directory Role" {
			graphToken, err := getGraphToken()
			if err != nil {
				return deactivateRoleResultMsg{Err: err}
			}

			body := map[string]interface{}{
				"action":           "selfDeactivate",
				"principalId":      userID,
				"roleDefinitionId": role.RoleDefinitionID,
				"directoryScopeId": role.ScopeID,
			}

			bodyJSON, err := json.Marshal(body)
			if err != nil {
				return deactivateRoleResultMsg{Err: err}
			}

			uri := "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
			_, err = graphRequest("POST", uri, graphToken, bodyJSON)
			if err != nil {
				return deactivateRoleResultMsg{Err: err}
			}
		}

		return deactivateRoleResultMsg{}
	}
}

func extendRoleCmd(userID string, role PimRole, justification string, durationHours int) tea.Cmd {
	return func() tea.Msg {
		durationStr := fmt.Sprintf("PT%dH", durationHours)

		if role.Type == "Azure Resource" {
			reqGUID, err := newUUID()
			if err != nil {
				return extendRoleResultMsg{Err: err}
			}

			body := map[string]interface{}{
				"properties": map[string]interface{}{
					"roleDefinitionId":                role.RoleDefinitionID,
					"principalId":                     userID,
					"scope":                           role.ScopeID,
					"justification":                   justification,
					"action":                          "SelfExtend",
					"linkedRoleEligibilityScheduleId": role.ScheduleName,
					"scheduleInfo": map[string]interface{}{
						"startDateTime": nil,
						"expiration": map[string]interface{}{
							"type":     "afterDuration",
							"duration": durationStr,
						},
					},
				},
			}

			bodyJSON, err := json.Marshal(body)
			if err != nil {
				return extendRoleResultMsg{Err: err}
			}

			uri := fmt.Sprintf("https://management.azure.com%s/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/%s?api-version=2020-10-01", role.ScopeID, reqGUID)

			_, err = runAzCmd("rest", "--method", "put", "--url", uri, "--body", string(bodyJSON))
			if err != nil {
				return extendRoleResultMsg{Err: cleanErrorMessage(err)}
			}

		} else if role.Type == "Directory Role" {
			graphToken, err := getGraphToken()
			if err != nil {
				return extendRoleResultMsg{Err: err}
			}

			body := map[string]interface{}{
				"action":           "selfExtend",
				"principalId":      userID,
				"roleDefinitionId": role.RoleDefinitionID,
				"directoryScopeId": role.ScopeID,
				"justification":    justification,
				"scheduleInfo": map[string]interface{}{
					"startDateTime": nil,
					"expiration": map[string]interface{}{
						"type":     "afterDuration",
						"duration": durationStr,
					},
				},
			}

			bodyJSON, err := json.Marshal(body)
			if err != nil {
				return extendRoleResultMsg{Err: err}
			}

			uri := "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
			_, err = graphRequest("POST", uri, graphToken, bodyJSON)
			if err != nil {
				return extendRoleResultMsg{Err: err}
			}
		}

		return extendRoleResultMsg{}
	}
}

// -------------------------------------------------------------
// Bubble tea model and run loop
// -------------------------------------------------------------

type model struct {
	width, height      int
	state              string // "init", "loading", "ready", "modal", "error", "device_code"
	loadingMsg         string
	err                error
	entraErr           error

	userID             string
	userName           string
	tenantName         string
	tenantID           string

	roles              []PimRole
	cursor             int
	scrollOffset       int
	lastUpdated        time.Time

	// Modal State
	selectedRole       PimRole
	justificationInput textinput.Model
	durationInput      textinput.Model
	focusedInput       int // 0: justification, 1: duration
	submitting         bool
	modalAction        string // "activate" or "extend"

	// Device Code State
	deviceCode         string
	deviceUrl          string

	spinner            spinner.Model
}

func initialModel() model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7aa2f7"))

	ji := textinput.New()
	ji.Placeholder = "Reason (optional)"
	ji.CharLimit = 80
	ji.Width = 40

	di := textinput.New()
	di.Placeholder = "8"
	di.SetValue("8")
	di.CharLimit = 2
	di.Width = 5

	return model{
		state:              "init",
		loadingMsg:         "Initializing, checking Azure session...",
		spinner:            s,
		justificationInput: ji,
		durationInput:      di,
		focusedInput:       0,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		initInfoCmd,
		tickCmd(),
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		cmds = append(cmds, tickCmd())
		return m, tea.Batch(cmds...)

	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
		return m, tea.Batch(cmds...)

	case deviceCodeMsg:
		m.state = "device_code"
		m.deviceCode = msg.UserCode
		m.deviceUrl = msg.VerificationURL
		return m, nil

	case initInfoMsg:
		if msg.Err != nil {
			m.state = "error"
			m.err = msg.Err
			return m, nil
		}
		m.userID = msg.UserID
		m.userName = msg.UserName
		m.tenantName = msg.TenantName
		m.tenantID = msg.TenantID

		m.state = "loading"
		m.loadingMsg = "Fetching eligible Entra PIM roles..."
		return m, fetchRolesCmd(m.userID)

	case fetchRolesMsg:
		if msg.Err != nil {
			m.state = "error"
			m.err = msg.Err
			return m, nil
		}
		m.roles = msg.Roles
		m.entraErr = msg.EntraErr
		m.lastUpdated = time.Now()
		m.state = "ready"
		
		if m.cursor >= len(m.roles) {
			m.cursor = max(0, len(m.roles)-1)
		}
		return m, nil

	case activateRoleResultMsg:
		m.submitting = false
		if msg.Err != nil {
			m.state = "error"
			m.err = msg.Err
			return m, nil
		}
		m.state = "loading"
		m.loadingMsg = "Success! Reloading roles..."
		return m, fetchRolesCmd(m.userID)

	case deactivateRoleResultMsg:
		m.submitting = false
		if msg.Err != nil {
			m.state = "error"
			m.err = msg.Err
			return m, nil
		}
		m.state = "loading"
		m.loadingMsg = "Deactivated successfully! Reloading roles..."
		return m, fetchRolesCmd(m.userID)

	case extendRoleResultMsg:
		m.submitting = false
		if msg.Err != nil {
			m.state = "error"
			m.err = msg.Err
			return m, nil
		}
		m.state = "loading"
		m.loadingMsg = "Extended successfully! Reloading roles..."
		return m, fetchRolesCmd(m.userID)

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		switch m.state {
		case "error":
			if msg.String() == "esc" || msg.String() == "enter" {
				m.err = nil
				if m.userID == "" {
					return m, tea.Quit
				}
				m.state = "ready"
				return m, nil
			}

		case "ready":
			switch msg.String() {
			case "q", "esc":
				return m, tea.Quit
			case "r":
				m.state = "loading"
				m.loadingMsg = "Refreshing PIM roles..."
				return m, fetchRolesCmd(m.userID)
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.roles)-1 {
					m.cursor++
				}
			case "enter", "a":
				if len(m.roles) > 0 {
					role := m.roles[m.cursor]
					if role.Status == "Eligible" {
						m.selectedRole = role
						m.modalAction = "activate"
						m.state = "modal"
						m.justificationInput.SetValue("")
						m.justificationInput.Placeholder = "Reason for activation (optional)"
						m.focusedInput = 0
						m.justificationInput.Focus()
						m.durationInput.Blur()
					} else if role.Status == "Active" {
						m.err = errors.New("this role is already activated")
						m.state = "error"
					} else {
						m.err = errors.New("permanent assignments cannot be activated")
						m.state = "error"
					}
				}
			case "d":
				if len(m.roles) > 0 {
					role := m.roles[m.cursor]
					if role.Status == "Active" {
						m.selectedRole = role
						m.state = "deactivate_modal"
					} else {
						m.err = errors.New("only active roles can be deactivated")
						m.state = "error"
					}
				}
			case "e":
				if len(m.roles) > 0 {
					role := m.roles[m.cursor]
					if role.Status == "Active" {
						m.selectedRole = role
						m.modalAction = "extend"
						m.state = "modal"
						m.justificationInput.SetValue("")
						m.justificationInput.Placeholder = "Reason for extension (optional)"
						m.focusedInput = 0
						m.justificationInput.Focus()
						m.durationInput.Blur()
					} else {
						m.err = errors.New("only active roles can be extended")
						m.state = "error"
					}
				}
			}

		case "deactivate_modal":
			switch msg.String() {
			case "esc":
				m.state = "ready"
				return m, nil
			case "enter":
				m.submitting = true
				m.state = "loading"
				m.loadingMsg = fmt.Sprintf("Deactivating role %s...", m.selectedRole.RoleName)
				return m, deactivateRoleCmd(m.userID, m.selectedRole)
			}

		case "modal":
			switch msg.String() {
			case "esc":
				m.state = "ready"
				return m, nil

			case "tab", "up", "down":
				m.focusedInput = 1 - m.focusedInput
				if m.focusedInput == 0 {
					m.justificationInput.Focus()
					m.durationInput.Blur()
				} else {
					m.justificationInput.Blur()
					m.durationInput.Focus()
				}
				return m, nil

			case "enter":
				val := strings.TrimSpace(m.durationInput.Value())
				hours, err := strconv.Atoi(val)
				if err != nil || hours < 1 || hours > 24 {
					durationMsg := "activation duration must be a number between 1 and 24 hours"
					if m.modalAction == "extend" {
						durationMsg = "extension duration must be a number between 1 and 24 hours"
					}
					m.err = errors.New(durationMsg)
					m.state = "error"
					return m, nil
				}

				justification := strings.TrimSpace(m.justificationInput.Value())
				if justification == "" {
					if m.modalAction == "extend" {
						justification = "Extended role via TUI"
					} else {
						justification = "Activating role via TUI"
					}
				}

				m.submitting = true
				m.state = "loading"
				if m.modalAction == "extend" {
					m.loadingMsg = fmt.Sprintf("Submitting extension for %s...", m.selectedRole.RoleName)
					return m, extendRoleCmd(m.userID, m.selectedRole, justification, hours)
				} else {
					m.loadingMsg = fmt.Sprintf("Submitting activation for %s...", m.selectedRole.RoleName)
					return m, activateRoleCmd(m.userID, m.selectedRole, justification, hours)
				}
			}

			if m.focusedInput == 0 {
				m.justificationInput, cmd = m.justificationInput.Update(msg)
				return m, cmd
			} else {
				m.durationInput, cmd = m.durationInput.Update(msg)
				return m, cmd
			}
		}
	}

	return m, nil
}

func (m model) getRemainingStr(expiresDT time.Time) string {
	if expiresDT.IsZero() {
		return ""
	}
	diff := time.Until(expiresDT)
	if diff <= 0 {
		return "Expired"
	}
	hours := int(diff.Hours())
	minutes := int(diff.Minutes()) % 60
	seconds := int(diff.Seconds()) % 60
	return fmt.Sprintf("%02dh %02dm %02ds remaining", hours, minutes, seconds)
}

func (m model) View() string {
	if m.width < 70 || m.height < 12 {
		return "\n  Terminal too small.\n  Please resize to at least 80x15."
	}

	var sb strings.Builder

	// Header
	title := headerStyle.Render(" ⚡ tpim ⚡ ")
	userStr := infoStyle.Render(fmt.Sprintf(" User: %s | Tenant: %s ", m.userName, m.tenantName))
	spaces := max(0, m.width-lipgloss.Width(title)-lipgloss.Width(userStr))
	sb.WriteString(title + strings.Repeat(" ", spaces) + userStr + "\n\n")

	// Body
	switch m.state {
	case "init", "loading", "activating":
		spinnerStr := m.spinner.View()
		loading := fmt.Sprintf("\n\n   %s %s\n\n", spinnerStr, m.loadingMsg)
		sb.WriteString(loading)
		sb.WriteString(strings.Repeat("\n", max(0, m.height-lipgloss.Height(sb.String())-3)))

	case "error":
		var errContent strings.Builder
		errContent.WriteString(errorStyle.Render("⚡ ERROR ⚡\n\n"))
		errContent.WriteString(m.err.Error() + "\n\n")
		errContent.WriteString(lipgloss.NewStyle().Faint(true).Render("Press [Esc] or [Enter] to dismiss"))

		dialog := lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#f7768e")).
			Padding(1, 2).
			Width(min(60, m.width-4)).
			Render(errContent.String())
		
		sb.WriteString(lipgloss.Place(m.width, m.height-6, lipgloss.Center, lipgloss.Center, dialog))

	case "device_code":
		var content strings.Builder
		content.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7aa2f7")).Render("◤ DEVICE AUTHENTICATION REQUIRED ◢\n\n"))
		content.WriteString("To browse/activate Entra ID PIM roles, please authenticate.\n\n")
		content.WriteString("1. On another device, open this URL:\n   ")
		content.WriteString(lipgloss.NewStyle().Underline(true).Foreground(lipgloss.Color("#9ece6a")).Render(m.deviceUrl) + "\n\n")
		content.WriteString("2. Enter this code:\n   ")
		content.WriteString(lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#2f334d")).Foreground(lipgloss.Color("#e0af68")).Padding(0, 1).Render(m.deviceCode) + "\n\n")
		content.WriteString(lipgloss.NewStyle().Faint(true).Render("Waiting for authentication in browser... (Press Ctrl+C to cancel)"))

		dialog := modalStyle.Render(content.String())
		sb.WriteString(lipgloss.Place(m.width, m.height-6, lipgloss.Center, lipgloss.Center, dialog))

	case "deactivate_modal":
		var content strings.Builder
		content.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#f7768e")).Render("◤ CONFIRM DEACTIVATION ◢\n\n"))
		content.WriteString("Are you sure you want to deactivate this active role?\n\n")
		content.WriteString(fmt.Sprintf("Role:  %s\n", lipgloss.NewStyle().Bold(true).Render(m.selectedRole.RoleName)))
		content.WriteString(fmt.Sprintf("Scope: %s (%s)\n\n", m.selectedRole.ScopeName, m.selectedRole.ScopeType))
		content.WriteString("This will terminate your privileged session immediately.\n\n")
		content.WriteString(lipgloss.NewStyle().Faint(true).Render("Press [Enter] confirm deactivation  |  [Esc] cancel"))

		dialog := modalStyle.Render(content.String())
		sb.WriteString(lipgloss.Place(m.width, m.height-6, lipgloss.Center, lipgloss.Center, dialog))

	case "ready":
		if m.entraErr != nil {
			warnMsg := " ⚠ Entra ID Roles unavailable: " + m.entraErr.Error()
			warnStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color("#e0af68")). // Yellow
				Bold(true)
			sb.WriteString(warnStyle.Render(padTrunc(warnMsg, m.width)) + "\n\n")
		}

		if len(m.roles) == 0 {
			sb.WriteString("\n   No eligible or active roles found in PIM.\n\n")
			sb.WriteString(strings.Repeat("\n", max(0, m.height-lipgloss.Height(sb.String())-3)))
		} else {
			roleW := int(float64(m.width) * 0.32)
			scopeW := int(float64(m.width) * 0.34)
			typeW := int(float64(m.width) * 0.12)
			statusW := m.width - roleW - scopeW - typeW - 6

			tblHeader := lipgloss.NewStyle().
				Underline(true).
				Bold(true).
				Foreground(lipgloss.Color("#7aa2f7")).
				Render(fmt.Sprintf("  %s  %s  %s  %s",
					padTrunc("Role", roleW),
					padTrunc("Scope", scopeW),
					padTrunc("Type", typeW),
					padTrunc("Status", statusW),
				))
			sb.WriteString(tblHeader + "\n")

			maxRows := m.height - 7
			if m.entraErr != nil {
				maxRows -= 2
			}
			startRow := max(0, m.cursor-maxRows+2)
			endRow := min(len(m.roles), startRow+maxRows)

			for i := startRow; i < endRow; i++ {
				role := m.roles[i]
				isSelected := (i == m.cursor)

				var rowStr string
				statusVal := role.Status
				var statusStyle lipgloss.Style

				if role.Status == "Active" {
					rem := m.getRemainingStr(role.ExpiresDT)
					statusVal = "● Active (" + rem + ")"
					statusStyle = activeStatusStyle
				} else if role.Status == "Eligible" {
					statusVal = "○ Eligible"
					statusStyle = eligibleStatusStyle
				} else if role.Status == "Assigned" {
					statusVal = "● Permanent"
					statusStyle = assignedStatusStyle
				}

				rowContent := fmt.Sprintf("  %s  %s  %s  %s",
					padTrunc(role.RoleName, roleW),
					padTrunc(role.ScopeName, scopeW),
					padTrunc(role.Type, typeW),
					padTrunc(statusVal, statusW),
				)

				if isSelected {
					rowStr = selectedRowStyle.Width(m.width - 2).Render(rowContent)
				} else {
					statusStyled := statusStyle.Render(padTrunc(statusVal, statusW))
					rowContent = fmt.Sprintf("  %s  %s  %s  %s",
						padTrunc(role.RoleName, roleW),
						padTrunc(role.ScopeName, scopeW),
						padTrunc(role.Type, typeW),
						statusStyled,
					)
					rowStr = normalRowStyle.Render(rowContent)
				}
				sb.WriteString(rowStr + "\n")
			}
			rowsDrawn := endRow - startRow
			sb.WriteString(strings.Repeat("\n", max(0, maxRows-rowsDrawn)))
		}

	case "modal":
		var modalContent strings.Builder
		titleText := "◤ SELF-ACTIVATE PIM ROLE ◢"
		if m.modalAction == "extend" {
			titleText = "◤ EXTEND ROLE ACTIVATION ◢"
		}
		modalContent.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7aa2f7")).Render(titleText + "\n\n"))
		modalContent.WriteString(fmt.Sprintf("Role:  %s\n", m.selectedRole.RoleName))
		modalContent.WriteString(fmt.Sprintf("Scope: %s (%s)\n\n", m.selectedRole.ScopeName, m.selectedRole.ScopeType))

		justFocusStr := "  "
		if m.focusedInput == 0 {
			justFocusStr = "▸ "
		}
		modalContent.WriteString(justFocusStr + "Justification:\n  " + m.justificationInput.View() + "\n\n")

		durFocusStr := "  "
		if m.focusedInput == 1 {
			durFocusStr = "▸ "
		}
		modalContent.WriteString(durFocusStr + "Duration (hours, 1-24):\n  " + m.durationInput.View() + "\n\n")

		modalContent.WriteString(lipgloss.NewStyle().Faint(true).Render("Press [Tab] switch field  |  [Enter] confirm  |  [Esc] cancel"))

		dialog := modalStyle.Render(modalContent.String())
		sb.WriteString(lipgloss.Place(m.width, m.height-6, lipgloss.Center, lipgloss.Center, dialog))
	}

	// Footer
	sb.WriteString("\n")
	statusStr := " Status: Done "
	if m.state == "ready" {
		statusStr = fmt.Sprintf(" Last updated: %s ", m.lastUpdated.Format("15:04:05"))
	} else if m.state == "loading" || m.state == "init" || m.state == "activating" {
		statusStr = " Status: Loading... "
	}
	
	statusVal := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#a9b1d6")).
		Background(lipgloss.Color("#1f2335")).
		Render(statusStr)

	legend := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#ffffff")).
		Background(lipgloss.Color("#3b4261")).
		Render(" [↑/↓/j/k] Navigate  [Enter/a] Activate  [d] Deactivate  [e] Extend  [r] Refresh  [q] Quit ")

	footerSpaces := max(0, m.width-lipgloss.Width(statusVal)-lipgloss.Width(legend))
	sb.WriteString(statusVal + strings.Repeat(" ", footerSpaces) + legend)

	return sb.String()
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	globalProgram = p
	if _, err := p.Run(); err != nil {
		log.Fatalf("Alas, it seems we have encountered an error: %v", err)
		os.Exit(1)
	}
}
