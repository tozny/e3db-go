#!/bin/sh
# The purpose of this file is to install a default
# e3db profile configuration so tests can execute
# against a live server.

set -e

# Check if the config is already set
if [ ! -d "$HOME/.tozny/integration-test" ]; then
    mkdir -p "$HOME/.tozny/integration-test"
fi

cat > "$HOME/.tozny/integration-test/e3db.json" <<EOT
{
    "version":1,
    "api_url":"${API_URL}",
    "api_key_id":"${API_KEY_ID}",
    "api_secret":"${API_SECRET}",
    "client_id":"${CLIENT_ID}",
    "client_email":"${CLIENT_EMAIL}",
    "public_key":"${PUBLIC_KEY}",
    "private_key":"${PRIVATE_KEY}"
}
EOT
