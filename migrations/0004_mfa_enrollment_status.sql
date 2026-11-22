-- ==============================================================================
-- Cloudflare D1 Database Migration: 0004_mfa_enrollment_status.sql
-- Project: Design and Implementation of an Integrated Real-Time Security
--          Verification Framework for Serverless Cloud Applications
-- Description: Tracks explicit first-time Authenticator pairing completion
--              (mfa_enrolled) so unenrolled users receive one-time QR/key
--              pairing while already-enrolled accounts never expose secrets.
-- ==============================================================================

ALTER TABLE users ADD COLUMN mfa_enrolled INTEGER NOT NULL DEFAULT 0;

UPDATE users
SET mfa_enrolled = 1
WHERE COALESCE(last_totp_step, 0) > 0;
