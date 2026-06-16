package rules

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRecorder struct {
	pool *pgxpool.Pool
}

func NewPostgresRecorder(pool *pgxpool.Pool) *PostgresRecorder {
	return &PostgresRecorder{pool: pool}
}

func (r *PostgresRecorder) RecordManagedRuleSet(ctx context.Context, set ManagedRuleSet) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	var setID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO managed_rule_sets (name, provider, source, description, local_path, enabled, metadata, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (name)
		DO UPDATE SET provider = EXCLUDED.provider,
		              source = EXCLUDED.source,
		              description = EXCLUDED.description,
		              local_path = EXCLUDED.local_path,
		              enabled = EXCLUDED.enabled,
		              metadata = EXCLUDED.metadata,
		              updated_at = now()
		RETURNING id::text`,
		set.Name, set.Provider, set.Source, set.Description, set.LocalPath, set.Enabled, set.Metadata,
	).Scan(&setID); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO managed_rule_versions (managed_rule_set_id, version, source_uri, local_path, checksum_sha256, ruleset_snapshot)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (managed_rule_set_id, version)
		DO UPDATE SET source_uri = EXCLUDED.source_uri,
		              local_path = EXCLUDED.local_path,
		              checksum_sha256 = EXCLUDED.checksum_sha256,
		              ruleset_snapshot = EXCLUDED.ruleset_snapshot`,
		setID, set.Version.Version, set.Version.SourceURI, set.Version.LocalPath, set.Version.ChecksumSHA256, set.Version.RulesetSnapshot,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
