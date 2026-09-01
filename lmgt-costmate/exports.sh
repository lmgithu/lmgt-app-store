# TeslaMate Postgres lives in the lmgt-teslamate app. Umbrel derives that
# app's APP_PASSWORD as derive_entropy "app-lmgt-teslamate-seed-APP_PASSWORD".
# Reusing the same label gives this app the same password without exporting
# secrets from TeslaMate itself.
export APP_COSTMATE_TESLAMATE_DATABASE_HOST="lmgt-teslamate_database_1"
export APP_COSTMATE_TESLAMATE_DATABASE_PORT="5432"
export APP_COSTMATE_TESLAMATE_DATABASE_USER="teslamate"
export APP_COSTMATE_TESLAMATE_DATABASE_NAME="teslamate"
export APP_COSTMATE_TESLAMATE_DATABASE_PASS="$(derive_entropy "app-lmgt-teslamate-seed-APP_PASSWORD")"
