package run

import (
	"context"
	"fmt"

	"thunderstorm/collector/internal/exposure"
	"thunderstorm/collector/internal/ledger"
	"thunderstorm/collector/internal/model"
	"thunderstorm/collector/internal/output"
	awsprov "thunderstorm/collector/internal/providers/aws"
	azureprov "thunderstorm/collector/internal/providers/azure"
	gcpprov "thunderstorm/collector/internal/providers/gcp"
	"thunderstorm/collector/internal/scheduler"
)

// binding holds everything provider-specific that the generic collection flow in
// run.go needs, so the middle (registry → planner → scheduler → prober → facts →
// bundle) is identical for every cloud. AWS and GCP each populate one.
type binding struct {
	name    string // "aws" | "gcp"
	account string // AWS account id / GCP project id
	caller  string // caller ARN / GCP caller email — the default foothold

	cli          scheduler.Invoker
	setBlobDir   func(string)
	hasOp        func(string) bool
	classify     func(error) string
	fetchers     exposure.FetcherSet
	listFetchers exposure.ListFetcherSet

	// collectFacts runs the provider's facts tier (nil if none yet, e.g. GCP pre-M5d).
	collectFacts func(ctx context.Context, led *ledger.Ledger, b *output.Bundle, concurrency int) int

	collectable []string      // regional scope names (regions / locations)
	globalCall  string        // CallRegion for global tasks
	scopes      []model.Scope // for the coverage report + manifest

	discovered int // scopes discovered
	notOptedIn int // scopes not collectable
}

// setupProvider authenticates, discovers scope, and wires the provider adapter.
// Records the auth + scope-discovery tasks in the ledger (the foolproofness spine).
func setupProvider(ctx context.Context, opts Options, led *ledger.Ledger, onlyRegions map[string]bool) (*binding, error) {
	switch opts.Provider {
	case "aws":
		return setupAWS(ctx, opts, led, onlyRegions)
	case "gcp":
		return setupGCP(ctx, opts, led, onlyRegions)
	case "azure":
		return setupAzure(ctx, opts, led, onlyRegions)
	default:
		return nil, fmt.Errorf("unsupported provider %q (aws|gcp|azure)", opts.Provider)
	}
}

func setupAWS(ctx context.Context, opts Options, led *ledger.Ledger, onlyRegions map[string]bool) (*binding, error) {
	cli, err := awsprov.Load(ctx, opts.Profile, opts.BootstrapRegion)
	if err != nil {
		return nil, fmt.Errorf("aws auth: %w", err)
	}
	idTask := "global/aws:sts:caller-identity/sts:GetCallerIdentity"
	led.Plan(idTask, model.Scope{Provider: "aws", Global: true}, "aws:sts:caller-identity", "sts:GetCallerIdentity")
	led.Start(idTask)
	id, err := cli.CallerIdentity(ctx)
	if err != nil {
		led.Finish(idTask, model.OutcomeError, 0, err.Error())
		return nil, fmt.Errorf("sts:GetCallerIdentity failed (is the profile valid?): %w", err)
	}
	led.Finish(idTask, model.OutcomeOK, 1, "")

	regTask := "global/aws:ec2:region/ec2:DescribeRegions"
	led.Plan(regTask, model.Scope{Provider: "aws", Account: id.Account, Global: true}, "aws:ec2:region", "ec2:DescribeRegions")
	led.Start(regTask)
	regions, err := cli.Regions(ctx)
	if err != nil {
		led.Finish(regTask, model.OutcomeError, 0, err.Error())
		return nil, fmt.Errorf("ec2:DescribeRegions failed: %w", err)
	}
	led.Finish(regTask, model.OutcomeOK, len(regions), "")

	b := &binding{
		name: "aws", account: id.Account, caller: id.ARN, cli: cli,
		setBlobDir: cli.SetBlobDir, hasOp: awsprov.HasOp, classify: awsprov.Classify,
		fetchers: awsprov.ExposureFetchers(cli), listFetchers: awsprov.ExposureListFetchers(cli),
		globalCall: opts.BootstrapRegion,
		scopes:     []model.Scope{{Provider: "aws", Account: id.Account, Global: true}},
	}
	b.collectFacts = func(ctx context.Context, led *ledger.Ledger, out *output.Bundle, conc int) int {
		return awsprov.CollectFacts(ctx, cli, id.Account, b.collectable, opts.BootstrapRegion, led, out, conc)
	}
	for _, r := range regions {
		scope := model.Scope{Provider: "aws", Account: id.Account, Region: r.Name}
		b.scopes = append(b.scopes, scope)
		task := "aws/" + r.Name + "/scope"
		led.Plan(task, scope, "aws:region:scope", "region-scope")
		if !r.Collectable {
			led.Finish(task, model.OutcomeSkipped, 0, "not_opted_in")
			b.notOptedIn++
			continue
		}
		if onlyRegions != nil && !onlyRegions[r.Name] {
			led.Finish(task, model.OutcomeSkipped, 0, "excluded_by_--only-regions")
			continue
		}
		led.Finish(task, model.OutcomeOK, 0, "")
		b.collectable = append(b.collectable, r.Name)
	}
	b.discovered = len(regions)
	return b, nil
}

func setupAzure(ctx context.Context, opts Options, led *ledger.Ledger, onlyRegions map[string]bool) (*binding, error) {
	cli, err := azureprov.Load(ctx, opts.Subscription)
	if err != nil {
		return nil, fmt.Errorf("azure auth: %w", err)
	}
	idTask := "global/azure:arm:caller-identity/subscriptions.list"
	led.Plan(idTask, model.Scope{Provider: "azure", Global: true}, "azure:arm:caller-identity", "subscriptions.list")
	led.Start(idTask)
	id, err := cli.CallerIdentity(ctx)
	if err != nil {
		led.Finish(idTask, model.OutcomeError, 0, err.Error())
		return nil, fmt.Errorf("azure caller identity failed (is `az login` valid?): %w", err)
	}
	led.Finish(idTask, model.OutcomeOK, 1, "")

	b := &binding{
		name: "azure", account: id.Account, caller: id.Email, cli: cli,
		setBlobDir: cli.SetBlobDir, hasOp: azureprov.HasOp, classify: azureprov.Classify,
		fetchers: azureprov.ExposureFetchers(cli), listFetchers: azureprov.ExposureListFetchers(cli),
		globalCall: "", // Azure inventory is via Resource Graph (all subs in one call)
		scopes:     []model.Scope{{Provider: "azure", Account: id.Account, Global: true}},
	}
	b.collectFacts = func(ctx context.Context, led *ledger.Ledger, out *output.Bundle, conc int) int {
		return cli.CollectFacts(ctx, id.Account, led, out, conc)
	}
	// record every in-scope subscription as a discovered scope (coverage ledger).
	for _, sub := range cli.Subscriptions() {
		scope := model.Scope{Provider: "azure", Account: sub, Global: true}
		b.scopes = append(b.scopes, scope)
		task := "azure/" + sub + "/scope"
		led.Plan(task, scope, "azure:subscription:scope", "subscription-scope")
		led.Finish(task, model.OutcomeOK, 0, "")
	}
	b.discovered = len(cli.Subscriptions())
	return b, nil
}

func setupGCP(ctx context.Context, opts Options, led *ledger.Ledger, onlyRegions map[string]bool) (*binding, error) {
	cli, err := gcpprov.Load(ctx, opts.Project, opts.ImpersonateSA)
	if err != nil {
		return nil, fmt.Errorf("gcp auth: %w", err)
	}
	idTask := "global/gcp:iam:caller-identity/tokeninfo"
	led.Plan(idTask, model.Scope{Provider: "gcp", Global: true}, "gcp:iam:caller-identity", "oauth2:tokeninfo")
	led.Start(idTask)
	id, err := cli.CallerIdentity(ctx)
	if err != nil {
		led.Finish(idTask, model.OutcomeError, 0, err.Error())
		return nil, fmt.Errorf("gcp caller identity failed (is ADC valid? run 'gcloud auth application-default login'): %w", err)
	}
	led.Finish(idTask, model.OutcomeOK, 1, "")
	// Non-identifying auth diagnostic (credential type only — no email/key/token) so it's
	// obvious whether an SA key was actually picked up as ADC.
	if !opts.Quiet {
		fmt.Printf("gcp auth: %s\n", cli.AuthDescriptor())
	}

	locTask := "global/gcp:compute:region/compute.regions.list"
	led.Plan(locTask, model.Scope{Provider: "gcp", Account: id.Account, Global: true}, "gcp:compute:region", "compute.regions.list")
	led.Start(locTask)
	locs, err := cli.Scopes(ctx)
	if err != nil {
		led.Finish(locTask, model.OutcomeError, 0, err.Error())
		return nil, fmt.Errorf("gcp location discovery failed: %w", err)
	}
	led.Finish(locTask, model.OutcomeOK, len(locs), "")

	b := &binding{
		name: "gcp", account: id.Account, caller: id.Email, cli: cli,
		setBlobDir: cli.SetBlobDir, hasOp: gcpprov.HasOp, classify: gcpprov.Classify,
		fetchers: gcpprov.ExposureFetchers(cli), listFetchers: gcpprov.ExposureListFetchers(cli),
		globalCall: "", // GCP global ops carry no {location}
		scopes:     []model.Scope{{Provider: "gcp", Account: id.Account, Global: true}},
	}
	b.collectFacts = func(ctx context.Context, led *ledger.Ledger, out *output.Bundle, conc int) int {
		return cli.CollectFacts(ctx, id.Account, b.collectable, led, out, conc)
	}
	for _, l := range locs {
		scope := model.Scope{Provider: "gcp", Account: id.Account, Region: l.Name}
		b.scopes = append(b.scopes, scope)
		task := "gcp/" + l.Name + "/scope"
		led.Plan(task, scope, "gcp:location:scope", "location-scope")
		if onlyRegions != nil && !onlyRegions[l.Name] {
			led.Finish(task, model.OutcomeSkipped, 0, "excluded_by_--only-regions")
			continue
		}
		led.Finish(task, model.OutcomeOK, 0, "")
		b.collectable = append(b.collectable, l.Name)
	}
	b.discovered = len(locs)
	return b, nil
}
