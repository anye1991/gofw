package enforce

import (
	"testing"

	"gofw/config"
)

func TestBuildScript(t *testing.T) {
	rs, err := config.Load("../rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	n := &NftablesEnforcer{}
	script := n.buildScript(rs)
	t.Log(script)
	if len(script) == 0 {
		t.Error("empty script")
	}
}
