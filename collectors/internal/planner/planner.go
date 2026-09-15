// Package planner expands the Resource Registry across discovered scopes into
// the DAG's seed (enumerate) tasks. Detail tasks are
// spawned dynamically by the scheduler as enumerations return.
package planner

import (
	"fmt"

	"thunderstorm/collector/internal/model"
	"thunderstorm/collector/internal/registry"
	"thunderstorm/collector/internal/scheduler"
)

// Seed builds one enumerate task per (resource type × applicable scope):
// global resources once; regional resources once per collectable region.
// bootstrapRegion is the region used for GLOBAL API calls (a global op must
// still sign against a real region — an empty region breaks endpoint resolution).
func Seed(reg *registry.Registry, account string, regions []string, bootstrapRegion string) []scheduler.Task {
	var tasks []scheduler.Task
	for i := range reg.Resources {
		rt := &reg.Resources[i]
		switch rt.Scope {
		case "regional":
			for _, r := range regions {
				scope := model.Scope{Provider: reg.Provider, Account: account, Region: r}
				tasks = append(tasks, enumTask(scope, r, rt))
			}
		default: // "global" (and unknown, treated as global)
			scope := model.Scope{Provider: reg.Provider, Account: account, Global: true}
			tasks = append(tasks, enumTask(scope, bootstrapRegion, rt))
		}
	}
	return tasks
}

func enumTask(scope model.Scope, callRegion string, rt *registry.ResourceType) scheduler.Task {
	loc := scope.Region
	if scope.Global {
		loc = "global"
	}
	return scheduler.Task{
		ID:         fmt.Sprintf("%s/%s/%s", loc, rt.ResourceType, rt.Enumerate.Operation),
		Scope:      scope,
		CallRegion: callRegion,
		Res:        rt,
		Op:         rt.Enumerate.Operation,
		Step:       -1,
		Params:     map[string]string{},
		Record:     map[string]any{},
	}
}
