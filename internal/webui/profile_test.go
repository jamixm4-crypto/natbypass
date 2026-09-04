package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/natbypass/natbypass/internal/config"
)

func TestProfileCreateListAndSwitch(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.yaml")

	// Create initial default config
	initCfg := &config.Config{}
	initProf := config.GenerateDefaultProfile("Main Network")
	initCfg.Profiles = []config.Profile{initProf}
	initCfg.ActiveProfileID = initProf.ID
	if err := config.Save(initCfg, cfgPath, false); err != nil {
		t.Fatalf("failed to save init config: %v", err)
	}

	s := NewServer(0, "admin", "secret", nil, nil)
	s.SetConfigPath(cfgPath)

	var reloadedCfg *config.Config
	s.SetOnProfileSwitch(func(p *config.Profile) error {
		if p != nil {
			var err error
			reloadedCfg, err = config.Load(cfgPath)
			if err != nil {
				t.Fatalf("onProfileSwitch: failed to reload config: %v", err)
			}
		}
		return nil
	})

	// 1. Check initial profiles list
	wList := httptest.NewRecorder()
	rList := httptest.NewRequest("GET", "/api/profiles", nil)
	s.handleProfilesList(wList, rList)
	if wList.Code != http.StatusOK {
		t.Fatalf("GET /api/profiles expected 200, got %d", wList.Code)
	}

	var listResp struct {
		Ok   bool `json:"ok"`
		Data struct {
			Profiles []config.Profile `json:"profiles"`
			ActiveID string           `json:"active_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(wList.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal profiles list failed: %v", err)
	}
	if len(listResp.Data.Profiles) != 1 {
		t.Fatalf("expected 1 profile initially, got %d", len(listResp.Data.Profiles))
	}

	// 2. Create a new profile with auto_switch: true
	createReqBody := map[string]interface{}{
		"name":        "Second Mesh Network",
		"mqtt_topic":  "natbypass/mesh/test-topic-second",
		"mqtt_broker": "tcp://broker.emqx.io:1883",
		"auto_switch": true,
	}
	createJSON, _ := json.Marshal(createReqBody)
	wCreate := httptest.NewRecorder()
	rCreate := httptest.NewRequest("POST", "/api/profiles/create", bytes.NewReader(createJSON))
	s.handleProfileCreate(wCreate, rCreate)
	if wCreate.Code != http.StatusOK {
		t.Fatalf("POST /api/profiles/create expected 200, got %d: %s", wCreate.Code, wCreate.Body.String())
	}

	var createResp struct {
		Ok   bool           `json:"ok"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(wCreate.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("unmarshal create resp failed: %v", err)
	}
	if !createResp.Ok {
		t.Fatalf("create response not ok: %s", wCreate.Body.String())
	}

	// 3. Verify that the reloaded config has 2 profiles and the new one is active
	if reloadedCfg == nil {
		t.Fatalf("expected onProfileSwitch to be called and reload config")
	}
	if len(reloadedCfg.Profiles) != 2 {
		t.Fatalf("expected 2 profiles in reloadedCfg, got %d", len(reloadedCfg.Profiles))
	}

	// 4. Verify that GET /api/profiles returns 2 profiles
	wList2 := httptest.NewRecorder()
	rList2 := httptest.NewRequest("GET", "/api/profiles", nil)
	s.handleProfilesList(wList2, rList2)
	if wList2.Code != http.StatusOK {
		t.Fatalf("GET /api/profiles expected 200, got %d", wList2.Code)
	}

	var listResp2 struct {
		Ok   bool `json:"ok"`
		Data struct {
			Profiles []config.Profile `json:"profiles"`
			ActiveID string           `json:"active_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(wList2.Body.Bytes(), &listResp2); err != nil {
		t.Fatalf("unmarshal profiles list 2 failed: %v", err)
	}
	if len(listResp2.Data.Profiles) != 2 {
		t.Fatalf("CRITICAL: expected 2 profiles after creation, but got %d! Profile did not appear!", len(listResp2.Data.Profiles))
	}
	if listResp2.Data.Profiles[1].Name != "Second Mesh Network" {
		t.Fatalf("expected profile name 'Second Mesh Network', got '%s'", listResp2.Data.Profiles[1].Name)
	}

	// 5. Verify switching back to the first profile
	firstID := listResp.Data.Profiles[0].ID
	switchReqBody := map[string]string{"id": firstID}
	switchJSON, _ := json.Marshal(switchReqBody)
	wSwitch := httptest.NewRecorder()
	rSwitch := httptest.NewRequest("POST", "/api/profiles/switch", bytes.NewReader(switchJSON))
	s.handleProfileSwitch(wSwitch, rSwitch)
	if wSwitch.Code != http.StatusOK {
		t.Fatalf("POST /api/profiles/switch expected 200, got %d", wSwitch.Code)
	}

	// 6. Verify first profile is active again
	wList3 := httptest.NewRecorder()
	rList3 := httptest.NewRequest("GET", "/api/profiles", nil)
	s.handleProfilesList(wList3, rList3)
	var listResp3 struct {
		Ok   bool `json:"ok"`
		Data struct {
			Profiles []config.Profile `json:"profiles"`
			ActiveID string           `json:"active_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(wList3.Body.Bytes(), &listResp3); err != nil {
		t.Fatalf("unmarshal profiles list 3 failed: %v", err)
	}
	if listResp3.Data.ActiveID != firstID {
		t.Fatalf("expected active profile to be '%s', got '%s'", firstID, listResp3.Data.ActiveID)
	}

	// 7. Test Profile Update: rename second profile
	secondID := listResp2.Data.Profiles[1].ID
	updateReqBody := map[string]interface{}{
		"id":         secondID,
		"name":       "Renamed Mesh Network",
		"mqtt_topic": "natbypass/mesh/renamed-topic",
	}
	updateJSON, _ := json.Marshal(updateReqBody)
	wUpdate := httptest.NewRecorder()
	rUpdate := httptest.NewRequest("POST", "/api/profiles/update", bytes.NewReader(updateJSON))
	s.handleProfileUpdate(wUpdate, rUpdate)
	if wUpdate.Code != http.StatusOK {
		t.Fatalf("POST /api/profiles/update expected 200, got %d: %s", wUpdate.Code, wUpdate.Body.String())
	}

	wList4 := httptest.NewRecorder()
	rList4 := httptest.NewRequest("GET", "/api/profiles", nil)
	s.handleProfilesList(wList4, rList4)
	var listResp4 struct {
		Data struct {
			Profiles []config.Profile `json:"profiles"`
		} `json:"data"`
	}
	_ = json.Unmarshal(wList4.Body.Bytes(), &listResp4)
	if len(listResp4.Data.Profiles) != 2 || listResp4.Data.Profiles[1].Name != "Renamed Mesh Network" {
		t.Fatalf("expected renamed profile, got %+v", listResp4.Data.Profiles)
	}

	// 8. Test Profile Delete: delete second profile
	delReqBody := map[string]string{"id": secondID}
	delJSON, _ := json.Marshal(delReqBody)
	wDel := httptest.NewRecorder()
	rDel := httptest.NewRequest("POST", "/api/profiles/delete", bytes.NewReader(delJSON))
	s.handleProfileDelete(wDel, rDel)
	if wDel.Code != http.StatusOK {
		t.Fatalf("POST /api/profiles/delete expected 200, got %d: %s", wDel.Code, wDel.Body.String())
	}

	wList5 := httptest.NewRecorder()
	rList5 := httptest.NewRequest("GET", "/api/profiles", nil)
	s.handleProfilesList(wList5, rList5)
	var listResp5 struct {
		Data struct {
			Profiles []config.Profile `json:"profiles"`
		} `json:"data"`
	}
	_ = json.Unmarshal(wList5.Body.Bytes(), &listResp5)
	if len(listResp5.Data.Profiles) != 1 {
		t.Fatalf("expected 1 profile after deletion, got %d", len(listResp5.Data.Profiles))
	}
}
