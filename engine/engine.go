// Package engine wires ingest, rules, replay, authorization and rate limiting
// into a single offline-runnable application facade.
package engine

import (
	"time"

	"github.com/lisama569/compliance-audit-engine-go/auth"
	"github.com/lisama569/compliance-audit-engine-go/ingest"
	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/ratelimit"
	"github.com/lisama569/compliance-audit-engine-go/replay"
	"github.com/lisama569/compliance-audit-engine-go/rules"
	"github.com/lisama569/compliance-audit-engine-go/store"
)

// Config configures the engine.
type Config struct {
	MaxLate                 time.Duration
	MaxSkew                 time.Duration
	RateLimitPerSec         float64
	RateLimitBurst          int
	RecomputePerSec         float64
	RecomputeBurst          int
	MaxRecomputeConcurrency int
}

// DefaultConfig returns sane local defaults.
func DefaultConfig() Config {
	return Config{
		MaxLate:                 72 * time.Hour,
		MaxSkew:                 5 * time.Minute,
		RateLimitPerSec:         0, // 0 = unlimited unless explicitly set
		RateLimitBurst:          1000,
		RecomputePerSec:         2,
		RecomputeBurst:          2,
		MaxRecomputeConcurrency: 2,
	}
}

// Engine is the application facade.
type Engine struct {
	cfg         Config
	Store       *store.Store
	registry    *rules.Registry
	pipeline    *ingest.Pipeline
	replayer    *replay.Replayer
	authz       *auth.Authorizer
	ingestRL    *ratelimit.Limiter
	recomputeRL *ratelimit.Limiter
	now         func() time.Time
}

// New constructs an Engine and publishes an initial global rule set so events
// can be ingested out of the box.
func New(cfg Config) *Engine {
	if cfg.MaxLate == 0 {
		cfg = DefaultConfig()
	}
	st := store.New()
	reg := rules.NewRegistry(st)
	pipe := ingest.NewPipeline(st, reg, ingest.Config{MaxLate: cfg.MaxLate, MaxSkew: cfg.MaxSkew, LateThreshold: 5 * time.Minute})
	rp := replay.NewReplayer(st, reg, cfg.MaxRecomputeConcurrency)
	return &Engine{
		cfg: cfg, Store: st, registry: reg, pipeline: pipe, replayer: rp,
		authz:       auth.NewAuthorizer(),
		ingestRL:    ratelimit.NewLimiter(cfg.RateLimitPerSec, cfg.RateLimitBurst),
		recomputeRL: ratelimit.NewLimiter(cfg.RecomputePerSec, cfg.RecomputeBurst),
		now:         time.Now,
	}
}

// SetClock overrides the clock across all components (tests).
func (e *Engine) SetClock(now func() time.Time) {
	e.now = now
	e.registry.SetClock(now)
	e.pipeline.SetClock(now)
	e.replayer.SetClock(now)
}

// Authz exposes the authorizer (primarily for tests/diagnostics).
func (e *Engine) Authz() *auth.Authorizer { return e.authz }

// RegisterTenant registers a tenant.
func (e *Engine) RegisterTenant(id string) { e.Store.RegisterTenant(id) }

// ---------- rule lifecycle ----------

// PublishRules publishes a new rule set version after authorization and
// validation. tenantID == "" targets the global scope (platform admin only).
func (e *Engine) PublishRules(p auth.Principal, tenantID string, rs []model.Rule, effectiveFrom time.Time) (*model.RuleSet, error) {
	if err := e.authz.Can(p, auth.ActionPublishRules, tenantID); err != nil {
		return nil, err
	}
	return e.registry.Publish(tenantID, rs, p.ID, effectiveFrom)
}

// RollbackRules publishes a new version copied from toVersion.
func (e *Engine) RollbackRules(p auth.Principal, tenantID string, toVersion int) (*model.RuleSet, error) {
	if err := e.authz.Can(p, auth.ActionRollbackRules, tenantID); err != nil {
		return nil, err
	}
	return e.registry.Rollback(tenantID, toVersion, p.ID)
}

// ListRuleVersions lists rule set versions within a scope.
func (e *Engine) ListRuleVersions(p auth.Principal, tenantID string) ([]*model.RuleSet, error) {
	if err := e.authz.Can(p, auth.ActionQuery, tenantID); err != nil {
		return nil, err
	}
	return e.registry.ListVersions(tenantID)
}

// ---------- ingestion ----------

// Ingest ingests one event with authorization and back-pressure.
func (e *Engine) Ingest(p auth.Principal, ev *model.Event) (*model.IngestResult, error) {
	if err := e.authz.Can(p, auth.ActionIngest, ev.TenantID); err != nil {
		return nil, err
	}
	if !e.ingestRL.Allow() {
		return nil, model.ErrOverloaded
	}
	return e.pipeline.Ingest(ev)
}

// ---------- queries ----------

// QueryDecisions returns current decisions for the caller's target tenant.
// The target tenant is always checked against the principal.
func (e *Engine) QueryDecisions(p auth.Principal, tenantID string, f store.DecisionFilter) ([]*model.Decision, error) {
	if err := e.authz.Can(p, auth.ActionQuery, tenantID); err != nil {
		return nil, err
	}
	return e.Store.QueryDecisions(tenantID, f)
}

// GetDecision returns one current decision.
func (e *Engine) GetDecision(p auth.Principal, tenantID, eventID string) (*model.Decision, error) {
	if err := e.authz.Can(p, auth.ActionQuery, tenantID); err != nil {
		return nil, err
	}
	return e.Store.CurrentDecision(tenantID, eventID)
}

// DecisionHistory returns the immutable original plus recomputation history.
func (e *Engine) DecisionHistory(p auth.Principal, tenantID, eventID string) (*model.Decision, []*model.Decision, error) {
	if err := e.authz.Can(p, auth.ActionQueryHistory, tenantID); err != nil {
		return nil, nil, err
	}
	orig, err := e.Store.GetOriginalDecision(tenantID, eventID)
	if err != nil {
		return nil, nil, err
	}
	return orig, e.Store.RecomputeHistory(tenantID, eventID), nil
}

// ListQuarantine lists isolated records (optionally by status).
func (e *Engine) ListQuarantine(p auth.Principal, tenantID, status string) ([]*model.QuarantineRecord, error) {
	if err := e.authz.Can(p, auth.ActionQuery, tenantID); err != nil {
		return nil, err
	}
	return e.Store.ListQuarantine(tenantID, status)
}

// ResolveQuarantine removes a resolved quarantine record.
func (e *Engine) ResolveQuarantine(p auth.Principal, tenantID, eventID string) error {
	if err := e.authz.Can(p, auth.ActionResolve, tenantID); err != nil {
		return err
	}
	e.Store.RemoveQuarantine(tenantID, eventID)
	return nil
}

// ---------- recomputation ----------

// RecomputeTenant recomputes all of a tenant's events. Bounded by a dedicated
// rate limiter and by worker concurrency; overload yields ErrOverloaded.
func (e *Engine) RecomputeTenant(p auth.Principal, tenantID string) (*replay.Report, error) {
	if err := e.authz.Can(p, auth.ActionRecompute, tenantID); err != nil {
		return nil, err
	}
	if !e.recomputeRL.Allow() {
		return nil, model.ErrOverloaded
	}
	return e.replayer.RecomputeTenant(tenantID, p.ID)
}

// RecomputeEvent recomputes one event.
func (e *Engine) RecomputeEvent(p auth.Principal, tenantID, eventID string) (*model.Decision, error) {
	if err := e.authz.Can(p, auth.ActionRecompute, tenantID); err != nil {
		return nil, err
	}
	if !e.recomputeRL.Allow() {
		return nil, model.ErrOverloaded
	}
	return e.replayer.RecomputeEvent(tenantID, eventID, p.ID)
}
