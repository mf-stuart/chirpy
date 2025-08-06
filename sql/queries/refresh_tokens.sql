-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token = $1;

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens(token, created_at, updated_at, expires_at, revoked_at, user_id)
VALUES
(
    $1,
    NOW(),
    NOW(),
    NOW() + INTERVAL '60 days',
    null,
    $2
)
RETURNING *;

-- name: SetRevoked :one
UPDATE refresh_tokens
SET revoked_at = NOW(),
    updated_at = NOW()
WHERE token = $1
RETURNING *;

-- name: GetUserByRefreshToken :one
SELECT * FROM users
INNER JOIN refresh_tokens ON users.id = refresh_tokens.user_id
WHERE refresh_tokens.token = $1;