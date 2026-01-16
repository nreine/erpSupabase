
-- Utiliser la service key pour exécuter ce genre de vue côté Postgres
CREATE OR REPLACE FUNCTION public.get_auth_user_by_email(p_email text)
RETURNS TABLE (id uuid, email text)
LANGUAGE sql
SECURITY DEFINER
AS $$
  SELECT u.id, u.email
  FROM auth.users u
  WHERE lower(u.email) = lower(p_email)
$$;
