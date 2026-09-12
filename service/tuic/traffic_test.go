package tuic

import (
	"errors"
	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/common/rule"
	"github.com/Mtoly/XrayRP/service/controller"
	log "github.com/sirupsen/logrus"
	"regexp"
	"testing"
	"time"
)

type emptyRulesAPI struct{ api.API }

func (emptyRulesAPI) ReportNodeStatus(*api.NodeStatus) error { return nil }
func (emptyRulesAPI) GetUserList() (*[]api.UserInfo, error) {
	return nil, errors.New(api.UserNotModified)
}
func (emptyRulesAPI) GetNodeRule() (*[]api.DetectRule, error) {
	rules := []api.DetectRule{}
	return &rules, nil
}

func TestClearRules(t *testing.T) {
	rules := rule.New()
	if err := rules.UpdateRule("node", []api.DetectRule{{ID: 1, Pattern: regexp.MustCompile("blocked")}}); err != nil {
		t.Fatal(err)
	}
	s := &TuicService{apiClient: emptyRulesAPI{}, config: &controller.Config{UpdatePeriodic: 1}, startAt: time.Now().Add(-time.Hour), logger: log.NewEntry(log.New()), rules: rules, tag: "node"}
	if err := s.userMonitor(); err != nil {
		t.Fatal(err)
	}
	if rules.Detect("node", "blocked.example", "1", "192.0.2.1") {
		t.Fatal("panel cleared rules but old rule still blocks traffic")
	}
}
