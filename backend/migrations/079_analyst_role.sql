-- Sprint 2: SOC analyst role between admin and readonly.
ALTER TYPE app_user_role ADD VALUE IF NOT EXISTS 'analyst';
