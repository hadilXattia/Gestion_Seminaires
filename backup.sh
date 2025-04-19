#!/bin/bash

# Config
DB_NAME="hadilxattia"
DB_USER="hadilxattia"
DB_HOST="localhost"
BACKUP_DIR="/path/to/backups"
DATE=$(date +\%F_\%H-\%M-\%S)
FILE_NAME="$DB_NAME-$DATE.sql"
S3_BUCKET="s3://local/db-backups"

# Create backup
mkdir -p $BACKUP_DIR
pg_dump -U $DB_USER -h $DB_HOST $DB_NAME > $BACKUP_DIR/$FILE_NAME

# Upload to S3
aws s3 cp $BACKUP_DIR/$FILE_NAME $S3_BUCKET

# Cleanup older than 7 days
find $BACKUP_DIR -type f -mtime +7 -delete
