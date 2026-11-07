-- The tenant as an OAuth and OpenID Connect provider (slice 6): an
-- authorization request waits as a challenge for the person's consent.
ALTER TABLE aos.challenges DROP CONSTRAINT challenges_kind_check;
ALTER TABLE aos.challenges ADD CONSTRAINT challenges_kind_check
    CHECK (kind IN ('passkey_registration', 'passkey_sign_in', 'pending_sign_in',
                    'oauth_state', 'saml_request', 'authorization_request'));
ALTER TABLE aos.oauth_clients ADD COLUMN description text;
