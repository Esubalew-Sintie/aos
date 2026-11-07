-- Strong sign-in (slice 5): a pending sign-in is found by the token the
-- browser holds, and devices are remembered per person.
ALTER TABLE aos.challenges ADD COLUMN token_hash bytea;
CREATE UNIQUE INDEX challenges_token ON aos.challenges (tenant_id, token_hash) WHERE token_hash IS NOT NULL;
CREATE INDEX tokens_target ON aos.tokens (tenant_id, purpose, target) WHERE used_at IS NULL;
