-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES
(
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: ResetUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: SetUserEmailById :one
UPDATE users
SET email = $2,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: SetUserHashedPasswordById :one
UPDATE users
SET hashed_password = $2,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpgradeUserByID :one
UPDATE users
SET is_chirpy_red = true,
    updated_at = NOW()
WHERE  id = $1
RETURNING *;