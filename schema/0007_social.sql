-- Social sign-in (slice 5): a generic OpenID Connect provider needs its issuer.
ALTER TABLE aos.oauth_providers ADD COLUMN issuer text;
