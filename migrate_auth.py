
# migrations/migrate_auth.py
import os
import sys
import time
from typing import Optional, Dict, Any

from supabase import create_client, Client
from dotenv import find_dotenv, load_dotenv

"""
Migration contrôlée vers Supabase Auth + profiles (schéma réel de Reine) :

Table source: public.utilisateurs
  - identifiant (TEXT)
  - role (TEXT)           -> mapping vers is_admin
  - actif (BOOLEAN)       -> on saute les comptes inactifs
  - email (TEXT)          -> obligatoire pour Auth

Table cible: public.profiles
  - id (UUID)             -> = auth.users.id
  - full_name (TEXT)      -> = identifiant
  - is_admin (BOOLEAN)    -> = (role == 'admin')
  - created_at (TIMESTAMPTZ) (auto)

Exécution :
    python migrations/migrate_auth.py --dry-run   # lecture seule
    python migrations/migrate_auth.py             # migration réelle
"""

# Chargement .env (cherche automatiquement à partir du CWD)
load_dotenv(find_dotenv(usecwd=True))

SUPABASE_URL = os.getenv("SUPABASE_URL")
SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
DEFAULT_PASSWORD = os.getenv("DEFAULT_PASSWORD", "Init-Password-2026!")

if not SUPABASE_URL or not SERVICE_ROLE_KEY:
    print("❌ SUPABASE_URL ou SUPABASE_SERVICE_ROLE_KEY manquants dans .env")
    sys.exit(1)

supabase: Client = create_client(SUPABASE_URL, SERVICE_ROLE_KEY)

# --- Logging ---
def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")

# --- Lecture utilisateurs (ADAPTÉ AUX COLONNES RÉELLES) ---
def fetch_existing_users() -> list[Dict[str, Any]]:
    """
    Lecture des utilisateurs depuis public.utilisateurs
    Champs utilisés : identifiant, role, actif, email
    """
    resp = supabase.table("utilisateurs").select(
        "identifiant, role, actif, email"
    ).execute()
    return resp.data or []

# --- RPC optionnelle: retrouver un auth.user existant par email (si déjà créé) ---
def get_existing_auth_user(email: str) -> Optional[Dict[str, Any]]:
    try:
        data = supabase.rpc("get_auth_user_by_email", {"p_email": email}).execute().data
        if data:
            return {"id": data[0]["id"], "email": data[0]["email"]}
    except Exception:
        pass
    return None

# --- Création utilisateur Auth ---
def create_auth_user(email: str, password: str, confirmed: bool = True) -> Optional[Dict[str, Any]]:
    """
    Crée l'utilisateur dans Supabase Auth (API Admin via service role).
    Si l'utilisateur existe déjà, retourne son UUID via RPC.
    """
    try:
        res = supabase.auth.admin.create_user({
            "email": email,
            "password": password,
            "email_confirm": confirmed
        })
        user = getattr(res, "user", None)
        if user and getattr(user, "id", None):
            return {"id": user.id, "email": user.email}
        # Si aucun user renvoyé, tenter la récupération via RPC (cas 'already registered')
        return get_existing_auth_user(email)
    except Exception as e:
        msg = str(e).lower()
        if "already" in msg or "exists" in msg:
            return get_existing_auth_user(email)
        log(f"❌ Erreur création Auth user ({email}): {e}")
        return None

# --- Upsert profile selon ton schéma ---

def ensure_profile(user_id: str, identifiant: str, email: str, role: str, actif: bool) -> bool:
    """
    Upsert dans public.profil: id, identifiant, email, role, actif
    """
    try:
        supabase.table("profil").upsert({
            "id": user_id,
            "identifiant": identifiant,
            "email": email,
            "role": role or "operateur",
            "actif": bool(actif)
        }, on_conflict="id").execute()
        return True
    except Exception as e:
        log(f"❌ Erreur upsert profil {identifiant} ({user_id}): {e}")
        return False


def rollback_auth_user(user_id: str) -> None:
    """
    Supprime le compte Auth si la création du profil a échoué.
    """
    try:
        supabase.auth.admin.delete_user(user_id)
        log(f"↩️ Rollback: utilisateur Auth supprimé ({user_id})")
    except Exception as e:
        log(f"⚠️ Rollback impossible pour {user_id}: {e}")

# --- Main ---
def main(dry_run: bool = False):
    users = fetch_existing_users()
    if not users:
        log("ℹ️ Aucun utilisateur à migrer (vérifie les colonnes lues: identifiant, role, actif, email).")
        return

    log(f"🔎 Utilisateurs à traiter: {len(users)}")
    migrated = 0
    skipped = 0
    failed = 0

    for u in users:
        identifiant = u.get("identifiant")
        role = (u.get("role") or "").strip().lower()
        actif = bool(u.get("actif", True))
        email = u.get("email")

        if not identifiant:
            log("⚠️ Ligne sans 'identifiant' → SKIP")
            skipped += 1
            continue

        if not email:
            log(f"⚠️ {identifiant}: pas d'email → SKIP (ou générer un alias si nécessaire).")
            skipped += 1
            continue

        if not actif:
            log(f"ℹ️ {identifiant}: compte inactif → SKIP (ne pas créer dans Auth).")
            skipped += 1
            continue

        is_admin = (role == "admin")
        log(f"➡️ {identifiant} / {email} / role={role} / is_admin={is_admin} / actif={actif}")

        if dry_run:
            continue

        # 1) Créer ou retrouver Auth user
        auth_user = create_auth_user(email, DEFAULT_PASSWORD, confirmed=True)
        if not auth_user or not auth_user.get("id"):
            log(f"❌ {identifiant}: échec création/récupération Auth")
            failed += 1
            continue

        auth_uuid = auth_user["id"]
        log(f"✅ Auth OK: {email} → {auth_uuid}")

        # 2) Créer/upsert le profil lié (id = auth.users.id)
        
        ok = ensure_profile(
            auth_uuid,
            identifiant=identifiant,
            email=email,
            role=(u.get("role") or "operateur"),
            actif=bool(u.get("actif", True))
        )

        migrated += 1

    log(f"📊 Résultat: migrated={migrated} | skipped={skipped} | failed={failed}")

if __name__ == "__main__":
    import traceback
    dry_run = "--dry-run" in sys.argv
    try:
        print("[DEBUG] Starting migration. dry_run =", dry_run)
        main(dry_run=dry_run)
        print("[DEBUG] Migration finished.")
    except Exception as e:
        print("❌ Exception during migration:", e)
        traceback.print_exc()
