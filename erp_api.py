import math
import streamlit as st
from supabase import create_client
import jwt  # pyjwt
import time
import pandas as pd
from datetime import date
import hashlib

import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from sklearn.linear_model import LinearRegression
import streamlit as st
import streamlit.components.v1 as components
from numpy.random import default_rng as rng

st.set_page_config(
    page_title="DSTM",
    page_icon="Designer.png"  # ton icône
)

# Connexion à Supabase
url = st.secrets["supabase_url"]
anon_key = st.secrets["supabase_anon_key"]
key = st.secrets["supabase_key"]
supabase = create_client(url, key)
JWT_SECRET = st.secrets["SUPABASE_JWT_SECRET"]
JWT_ALG = "HS256"


# Fonction de hachage du mot de passe
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- Utilitaires ---
def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def make_supabase_compatible_jwt(user_id: str, ttl_seconds: int = 7200) -> str:
    now = int(time.time())
    payload = {
        "sub": user_id,           # 🔑 auth.uid() = sub
        "role": "authenticated",  # 🔐 rôle PostgREST
        "iat": now,
        "exp": now + ttl_seconds,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    return token if isinstance(token, str) else token.decode("utf-8")


# Stocker le client dans la session pour pouvoir le recréer au besoin
if "supabase_client" not in st.session_state:
    st.session_state["supabase_client"] = create_client(url, anon_key)
supabase = st.session_state["supabase_client"]

def set_bearer(token: str):
    """Attache le Bearer JWT au client PostgREST (RLS)."""
    # Méthode officielle (v2.x)
    supabase.postgrest.auth(token)

def clear_bearer():
    """Retire le Bearer JWT du client PostgREST (RLS)."""
    try:
        # Méthode officielle (v2.x)
        supabase.postgrest.auth(None)
    except Exception:
        # Fallback universel : recréer un client propre sans Authorization
        st.session_state["supabase_client"] = create_client(url, anon_key)


def logout():
    clear_bearer()
    for k in ["user_id", "role", "display_name", "bearer_token", "doit_changer_mdp"]:
        st.session_state.pop(k, None)

# --- Auth fusionnée SHA + JWT ---
def authenticate_user(identifiant: str, password_plain: str) -> bool:
    """1) Vérifie SHA-256 via RPC, 2) Génère JWT, 3) Stocke session."""
    pass_hash = sha256_hex(password_plain)
    try:
        res = supabase.rpc("login_utilisateur", {"ident": identifiant, "pass_hash": pass_hash}).execute()
        rows = res.data or []
        if not rows:
            st.error("❌ Identifiant ou mot de passe incorrect.")
            return False

        user = rows[0]
        user_id = user["user_id"]
        role = user.get("role", "operateur")
        display_name = user.get("display_name", identifiant)
        doit_changer_mdp = bool(user.get("doit_changer_mdp", False))

        # 🔐 JWT pour RLS
        token = make_supabase_compatible_jwt(user_id)
        set_bearer(token)

        # ✅ Session unique
        st.session_state["user_id"] = user_id
        st.session_state["role"] = role
        st.session_state["display_name"] = display_name
        st.session_state["bearer_token"] = token
        st.session_state["doit_changer_mdp"] = doit_changer_mdp

        return True
    except Exception as e:
        st.error(f"Erreur lors du login : {e}")
        return False

# --- Page de connexion (formulaire unique, AVANT main) ---
def show_login_form() -> bool:
    st.markdown("<h2 style='text-align: center;'> 🔐 Connexion à l'application DSTM</h2>", unsafe_allow_html=True)
    st.markdown("<div style='text-align: center;'>Veuillez entrer vos identifiants pour accéder à l'application.</div>", unsafe_allow_html=True)
    st.divider()
    with st.container(border=True):
        st.image("imageExcelis.png", width=200)
        st.markdown("<h6 style='text-align: center; color: grey;'><em>Département Cartes et Partenariat DCP</em></h6>", unsafe_allow_html=True)
        st.markdown("<div style='display: flex; justify-content: center;'>", unsafe_allow_html=True)
        col1, col2 = st.columns([1, 2])
        with col2:
            ident = st.text_input("Identifiant", key="login_ident")
            pwd = st.text_input("Mot de passe", type="password", key="login_pwd")
            if st.button("✅ Se connecter", type="secondary"):
                if authenticate_user(ident, pwd):
                    st.success("✅ Connexion réussie")
                    st.rerun()
                return False
        st.markdown("</div>", unsafe_allow_html=True)

# --- Page de changement de mot de passe (première session) ---
def show_change_password():
    st.warning("🔄 Vous devez changer votre mot de passe avant d'accéder aux modules.")
    new_pwd = st.text_input("Nouveau mot de passe", type="password", key="new_pwd")
    confirm = st.text_input("Confirmer le mot de passe", type="password", key="confirm_pwd")
    if st.button("✅ Mettre à jour"):
        if not new_pwd:
            st.error("Le mot de passe ne peut pas être vide."); return
        if new_pwd != confirm:
            st.error("Les mots de passe ne correspondent pas."); return
        try:
            supabase.table("utilisateurs").update({
                "mot_de_passe": sha256_hex(new_pwd),
                "doit_changer_mdp": False
            }).eq("user_id", st.session_state["user_id"]).execute()
            st.success("✅ Mot de passe mis à jour. Bienvenue !")
            st.session_state["doit_changer_mdp"] = False
        except Exception as e:
            st.error(f"Erreur de mise à jour : {e}")

# --- ✅ PORTE D'AUTH HORS MAIN (toujours exécutée AVANT tout) ---
def ensure_authenticated():
    """
    Affiche le login tant que l'utilisateur n'est pas authentifié.
    Après login, si 'doit_changer_mdp' est vrai, force la page de changement de mot de passe.
    """
    if "bearer_token" not in st.session_state or "user_id" not in st.session_state:
        ok = show_login_form()
        if not ok:
            # Tant que non authentifié, on arrête l'app ici (pas de menu ni modules)
            st.stop()
        return

    # Auth OK mais premier login → changer le mot de passe avant l'accès aux modules
    if st.session_state.get("doit_changer_mdp", False):
        show_change_password()
        st.stop()

# --- 🚪 APPEL HORS MAIN : PORTE D'AUTH TOUJOURS EN PREMIER ---
ensure_authenticated()

if "lot_action" not in st.session_state:
    st.session_state["lot_action"] = None  # add | edit | delete
if "lot_id" not in st.session_state:
    st.session_state["lot_id"] = None


# Exemple d'enregistrement d'un lot
def enregistrer_lot():
    st.markdown("## ➕ Enregistrement d'un nouveau lot")
    st.divider()
    with st.form("form_enregistrement"):
        col1, col2 = st.columns(2)
        with col1:
            nom_lot = st.text_input("Nom du lot")
            type_lot = st.selectbox("Type de lot", ["Ordinaire", "Émission instantanée", "Renouvellement"])
            quantite = st.number_input("Quantité totale", min_value=1)
            date_production = st.date_input("Date de production", value=date.today())
        with col2:
            date_enregistrement = st.date_input("Date d'enregistrement", value=date.today())
            filiale = st.selectbox("Filiale", ["Burkina Faso", "Mali", "Niger", "Côte d'Ivoire", "Sénégal", "Bénin", "Togo", "Guinée Bissau", "Guinée Conakry"])
            impression_pin = st.radio("Impression de PIN ?", ["Oui", "Non"])
            nombre_pin = st.number_input("Nombre de PIN", min_value=1) if impression_pin == "Oui" else 0

        cartes_a_tester = int(quantite / 50) + (quantite % 50 > 0)
        submitted = st.form_submit_button("✅ Enregistrer le lot")
        

        if submitted:
            existing = supabase.table("lots").select("id").eq("nom_lot", nom_lot).execute().data
            if existing:
                st.error("❌ Ce nom de lot existe déjà. Vérifiez le nom de lot.")
            else:
                
# Récupérer le dernier ID
                last_id_data = supabase.table("lots").select("id").order("id", desc=True).limit(1).execute().data
                next_id = (last_id_data[0]["id"] + 1) if last_id_data else 1
                   
                supabase.table("lots").insert({
                    "id": next_id,
                    "nom_lot": nom_lot,
                    "type_lot": type_lot,
                    "quantite": quantite,
                    "date_production": str(date_production),
                    "date_enregistrement": str(date_enregistrement),
                    "filiale": filiale,
                    "impression_pin": impression_pin,
                    "nombre_pin": nombre_pin,
                    "cartes_a_tester": cartes_a_tester, 
                }).execute()
                st.success("✅ Lot enregistré avec succès.")
                st.rerun()

st.markdown("<h1 style='text-align: center;'>Gestion des activités de la section DCP</h1>", unsafe_allow_html=True)
st.divider()
# Menu latéral avec icône burger
with st.sidebar:
    st.image("imageExcelis.png", width=200)
    st.markdown("<h6 style='text-align: center; color: grey;'><em>Département Cartes et Partenariat DCP</em></h6>", unsafe_allow_html=True)
    
    menu = st.selectbox("Naviguer vers :", [
        "🏠 Accueil",
        "➕ Enregistrement des lots",
        "📋 Visualisation des lots",
        "🧪 Contrôle qualité",
        "🗂 Inventaire des tests",
        "📊 Graphiques et Analyses",
        "📦 Conditionnement des cartes",
        "🗂 Inventaire des conditionnements",
        "⚙️ Gestion des agences",
        "🚚 Expédition des lots",
        "📇 Annuaire des livreurs",
        "📦 Visualisation des expéditions",
        "🔐 Gestion des comptes utilisateurs"
    ])

def accueil_dashboard():
    import pandas as pd
    st.markdown("<h2 style='text-align:center;'>Accueil</h2>", unsafe_allow_html=True)
# 📦 Carte des lots enregistrés
    lots_data = supabase.table("lots").select("type_lot", "quantite").execute().data
    lots_df = pd.DataFrame(lots_data)

# Total des lots
    total_lots = len(lots_df)

# Agrégation par type
    repartition = lots_df.groupby("type_lot")["quantite"].sum().reset_index()

# Histogramme
    fig = px.bar(repartition, x="type_lot", y="quantite", text="quantite",
                title="📊 Répartition des types de lots enregistrés",
                labels={"type_lot": "Type de lot", "quantite": "Quantité"})
    fig.update_traces(marker_color="steelblue", textposition="outside")
    fig.update_layout(margin=dict(t=40, b=20))

# Affichage dans une carte élégante
    st.markdown(f"""
        <div style='border:1px solid #ccc; padding:25px; border-radius:15px; margin-bottom:30px;'>
            <h3 style='text-align:center;'>📦 Lots enregistrés</h3>
            <p style='text-align:center; font-size:18px;'>
                Nombre total de lots enregistrés : <strong>{total_lots}</strong>
            </p>
        </div>
    """, unsafe_allow_html=True)

    st.plotly_chart(fig, use_container_width=True)
    st.divider()

    
# 🧪 Carte des tests qualité
    controle_data = supabase.table("controle_qualite").select("quantite", "quantite_a_tester", "resultat").execute().data
    controle_df = pd.DataFrame(controle_data)

# Calculs
    total_enregistree = controle_df["quantite"].sum()
    total_testee = controle_df["quantite_a_tester"].sum()
    pourcentage = round((total_testee / total_enregistree) * 100, 2) if total_enregistree > 0 else 0

# Vérification du taux de réussite
    taux_100 = controle_df["resultat"].eq("Réussite").all()

# Données pour le diagramme en anneau
    donut_data = pd.DataFrame({
        "Catégorie": ["Cartes testées", "Cartes non testées"],
        "Quantité": [total_testee, total_enregistree - total_testee]
    })

    fig = px.pie(donut_data, names="Catégorie", values="Quantité", hole=0.5,title="🧪 Echantillonnage",
                color_discrete_sequence=["#4682B4", "#27d636"])
    fig.update_traces(textinfo="label+percent")


# Affichage dans une carte élégante
    description = f"""
        Cartes testées : <strong>{total_testee}</strong>
        """
    if taux_100:
        description += "<br><span style='color:green;'>✅ Taux de reussite des tests (100%)</span>"
    st.markdown(f"""
    <div style='border:1px solid #ccc; padding:25px; border-radius:15px; margin-bottom:30px;'>
        <h3 style='text-align:center;'>🧪 Tests qualité</h3>
        <p style='text-align:center; font-size:18px;'>{description}</p>
    </div>
    """, unsafe_allow_html=True)

    st.plotly_chart(fig, use_container_width=True)
    
    
# 🧪 Carte des tests qualité
    controle_data = supabase.table("controle_qualite").select("type_carte", "quantite", "quantite_a_tester").execute().data
    controle_df = pd.DataFrame(controle_data)

# Calcul du total testé
    total_testee = controle_df["quantite_a_tester"].sum()

# Agrégation par type
    repartition = controle_df.groupby("type_carte").agg({
        "quantite": "sum",
        "quantite_a_tester": "sum"
    }).reset_index()
    repartition["pourcentage_reussite"] = (repartition["quantite_a_tester"] / repartition["quantite"]) * 100
# Graphique
    fig = px.bar(repartition, x="type_carte", y="quantite", text="quantite_a_tester",
                title="🧪 Cartes enregistrées vs testées",
                labels={"quantite": "Cartes enregistrées", "quantite_a_tester": "Cartes testées"},
                color="pourcentage_reussite", color_continuous_scale=["#4682B4", "#2f4b7c", "#665191", "#a05195", "#d45087", "#f95d6a", "#ff7c43", "#ffa600"])
    fig.update_traces(texttemplate="%{text} testées", textposition="outside")
    fig.update_layout(margin=dict(t=40, b=20))

    st.plotly_chart(fig, use_container_width=True)
    st.divider()


# 🔹 Récupération des données des agences
    agences_data = supabase.table("agences_livraison").select("agence", "pays").execute().data
    agences_df = pd.DataFrame(agences_data)

    # 🔹 Récupération des données des expéditions
    expeditions_data = supabase.table("expedition").select("agence", "pays", "statut").execute().data
    expeditions_df = pd.DataFrame(expeditions_data)

    # ✅ 1. Affichage du total des agences
    total_agences = agences_df["agence"].nunique()
    description = f"""
        Agences disponibles : <strong>{total_agences}</strong>
        """
    st.markdown(f"""
    <div style='border:1px solid #ccc; padding:25px; border-radius:15px; margin-bottom:30px;'>
        <h3 style='text-align:center;'>🏢 Agences de livraison</h3>
        <p style='text-align:center; font-size:18px;'>{description}</p>
    </div>
    """, unsafe_allow_html=True)

    # ✅ 2. Préparation des données pour le graphique
    if not expeditions_df.empty:
        # Filtrer uniquement les expéditions avec statut "expédié"
        expeditions_filtre = expeditions_df[expeditions_df["statut"].str.lower() == "expédié"]

        # Calculer la quantité par agence et filiale (nombre d'enregistrements)
        repartition = expeditions_filtre.groupby(["agence", "pays"]).size().reset_index(name="quantite")

        # ✅ Graphique combiné : barres groupées par agence et filiale
        fig = px.bar(
            repartition,
            x="agence",
            y="quantite",
            color="pays",
            barmode="group",
            title="📦 Expéditions par agence et par filiale (statut = expédié)",
            labels={"agence": "Agence", "quantite": "Nombre d'expéditions", "pays": "Filiale"}
        )
        fig.update_layout(margin=dict(t=40, b=20), legend_title_text="Filiale")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("Aucune donnée d'expédition disponible pour le moment.")
    st.divider()

    
# 🔹 Récupération des données des utilisateurs
    utilisateurs_data = supabase.table("utilisateurs").select("identifiant", "actif").execute().data
    utilisateurs_df = pd.DataFrame(utilisateurs_data)

# ✅ Vérification si la table contient des données
    if not utilisateurs_df.empty:
        total_utilisateurs = len(utilisateurs_df)
        comptes_actifs = utilisateurs_df[utilisateurs_df["actif"] == True].shape[0]
        comptes_inactifs = total_utilisateurs - comptes_actifs

    # ✅ Affichage sous forme de card
        st.markdown("""
            <div style="background-color:#4682B4; padding:20px; border-radius:10px; text-align:center; box-shadow:0 2px 5px rgba(0,0,0,0.1);">
                <h4>👥 Utilisateurs</h4>
                <h2>{}</h2>
                <p>Comptes actifs : <b>{}</b> | Comptes inactifs : <b>{}</b></p>
            </div>
        """.format(total_utilisateurs, comptes_actifs, comptes_inactifs), unsafe_allow_html=True)
    else:
        st.warning("Aucun utilisateur enregistré pour le moment.")
    st.divider()

# Bloc Graphiques et Analyses
if menu == "🏠 Accueil":
    st.markdown("## Accueil")
    st.divider()

    changes = list(rng(4).standard_normal(20))
    data = [sum(changes[:i]) for i in range(20)]
    delta = round(data[-1], 2)

    # Récupération des données
    lots_data = supabase.table("lots").select("*").execute().data
    controle_data = supabase.table("controle_qualite").select("*").execute().data

    if not lots_data or not controle_data:
        st.warning("Aucune donnée disponible dans Supabase.")
    else:
        lots_df = pd.DataFrame(lots_data)
        controle_df = pd.DataFrame(controle_data)

        # Ajout des filiales aux contrôles
        lot_filiales = {lot["id"]: lot["filiale"] for lot in lots_data}
        controle_df["filiale"] = controle_df["lot_id"].map(lot_filiales)

        mois_en_fr = {
            'January': 'Janvier', 'February': 'Février', 'March': 'Mars', 'April': 'Avril',
            'May': 'Mai', 'June': 'Juin', 'July': 'Juillet', 'August': 'Août',
            'September': 'Septembre', 'October': 'Octobre', 'November': 'Novembre', 'December': 'Décembre'
        }
        semaine_en_fr = {
            'Monday': 'Lundi', 'Tuesday': 'Mardi', 'Wednesday': 'Mercredi', 'Thursday': 'Jeudi',
            'Friday': 'Vendredi', 'Saturday': 'Samedi', 'Sunday': 'Dimanche'
        }

        # Conversion des dates
        lots_df["date_enregistrement"] = pd.to_datetime(lots_df["date_enregistrement"], errors="coerce")
        controle_df["date_controle"] = pd.to_datetime(controle_df["date_controle"], errors="coerce")
        controle_df["Jour_Semaine"] = controle_df["date_controle"].dt.day_name().map(semaine_en_fr)     
        controle_df["Mois"] = controle_df["date_controle"].dt.month_name().map(mois_en_fr)
        lots_df["Mois"] = lots_df["date_enregistrement"].dt.month_name().map(mois_en_fr)
        lots_df["Trimestre"] = lots_df["date_enregistrement"].dt.quarter.astype(str)
        controle_df["Trimestre"] = controle_df["date_controle"].dt.quarter.astype(str)
      
        # Fusionner les mois des deux sources
        mois_lots = lots_df["Mois"].dropna().unique().tolist()
        mois_controle = controle_df["Mois"].dropna().unique().tolist()
        mois_combines = sorted(set(mois_lots + mois_controle), key=lambda x: mois_lots.index(x) if x in mois_lots else mois_controle.index(x))

        
        # Fusion des trimestres disponibles
        trimestres_lots = lots_df["Trimestre"].dropna().unique().tolist()
        trimestres_controle = controle_df["Trimestre"].dropna().unique().tolist()
        trimestres_combines = sorted(set(trimestres_lots + trimestres_controle), key=lambda x: int(x))

        
        st.sidebar.header("🔍 Filtres Graphiques")

        controle_df["date_controle"] = pd.to_datetime(controle_df["date_controle"], errors="coerce")
        min_date = controle_df["date_controle"].min().date()
        max_date = controle_df["date_controle"].max().date()
        date_range = st.sidebar.date_input("Période de contrôle", [min_date, max_date])

        filiales = controle_df["filiale"].dropna().unique().tolist()
        filiale_selection = st.sidebar.multiselect("Filiale", filiales, default=filiales)

        types_cartes = controle_df["type_carte"].dropna().unique().tolist()
        type_selection = st.sidebar.multiselect("Type de carte", types_cartes, default=types_cartes)

        
        jours = controle_df["Jour_Semaine"].dropna().unique().tolist()
        jour_selection = st.sidebar.multiselect("Jour de la semaine", jours, default=jours)

        
        # Filtre latéral unique
        mois_selection = st.sidebar.multiselect("Mois", mois_combines, default=mois_combines)

        
        # Filtre latéral unique
        trimestre_selection = st.sidebar.multiselect("Trimestre", trimestres_combines, default=trimestres_combines)

        
        controle_df_filtered = controle_df[
            (controle_df["date_controle"].dt.date >= date_range[0]) &
            (controle_df["date_controle"].dt.date <= date_range[1]) &
            (controle_df["filiale"].isin(filiale_selection)) &
            (controle_df["type_carte"].isin(type_selection)) &
            (controle_df["Jour_Semaine"].isin(jour_selection)) 
        ]
        
        # Appliquer le filtre aux deux DataFrames
        lots_df_filtered = lots_df[lots_df["Mois"].isin(mois_selection)]
        
        # Application du filtre aux deux DataFrames
        lots_df_filtered = lots_df[lots_df["Trimestre"].isin(trimestre_selection)]


        # KPIs sur les lots
        st.subheader("Lots Enregistrés")

        total_lots = len(lots_df_filtered)
        total_cartes = lots_df_filtered["quantite"].sum()
        moyenne_cartes = lots_df_filtered["quantite"].mean()
        lots_avec_pin = lots_df_filtered[lots_df_filtered["impression_pin"] == "Oui"].shape[0]

        col1, col2, col3= st.columns(3)

        col1.metric("Nombre total de lots", total_lots, f"{total_lots} lots enregistrés", border=True)
        col2.metric("Total cartes produites", total_cartes, f"{total_cartes} cartes enregistrées", border=True)
        #col3.metric("Moyenne cartes/lot", f"{moyenne_cartes:.2f}", f"{moyenne_cartes} ", border=True)
        col3.metric("Lots + PIN", lots_avec_pin, f"{lots_avec_pin} lots enregistrés avec PIN", border=True)

        
        with st.container(border=True):
        # Graphique Mesh3D production mensuelle
# Conversion des dates et extraction du mois
            lots_df_filtered["Mois"] = lots_df_filtered["date_enregistrement"].dt.month_name()
            lots_df_filtered["Mois"] = lots_df_filtered["Mois"].map({'January': 'Janvier', 'February': 'Février', 'March': 'Mars', 'April': 'Avril', 'May': 'Mai', 'June': 'Juin', 'July': 'Juillet', 'August': 'Août', 'September': 'Septembre', 'October': 'Octobre', 'November': 'Novembre', 'December': 'Décembre'})
# Agrégation mensuelle
            production_mensuelle = lots_df_filtered.groupby("Mois")["quantite"].sum().reset_index()
# Ordre des mois
            mois_ordonne = ["Janvier", "Février", "Mars", "Avril", "Mai", "Juin",
                   "Juillet", "Août", "Septembre", "Octobre", "Novembre", "Décembre"]
            production_mensuelle["Mois"] = pd.Categorical(production_mensuelle["Mois"], categories=mois_ordonne, ordered=True)
            production_mensuelle = production_mensuelle.sort_values("Mois")

# Coordonnées Mesh3D
            x = np.arange(len(production_mensuelle))
            y = np.zeros(len(production_mensuelle))
            z = production_mensuelle["quantite"].values
            i = list(range(len(x) - 2))
            j = [k + 1 for k in i]
            k = [k + 2 for k in i]

# Graphique Mesh3D
            fig = go.Figure(data=[
               go.Mesh3d(
                   x=x, y=y, z=z,
                   i=i, j=j, k=k,
                   intensity=z,
                   colorscale='Plasma',  # Palette personnalisée
                   opacity=0.9,
                   name="Production mensuelle"
               ),
               go.Scatter3d(
                  x=x,
                  y=y,
                  z=z + 500,
                  text=[f"{mois}<br>{val} cartes" for mois, val in zip(production_mensuelle["Mois"], z)],
                  mode="text",
                  showlegend=False
               )
             ])
            fig.update_layout(
               title="📦 Production mensuelle des cartes",
               scene=dict(
                   xaxis=dict(title="Mois", tickvals=x, ticktext=production_mensuelle["Mois"]),
                   yaxis=dict(title=""),
                   zaxis=dict(title="Quantité produite")
               ),
               margin=dict(l=0, r=0, b=0, t=40)
            )   
            st.plotly_chart(fig, use_container_width=True)
        
        col1, col2 = st.columns([2, 3])
        with col1:
            with st.container(border=True):
        # Graphique cônes 3D par type de lot
                types_lot = lots_df_filtered["type_lot"].unique().tolist()
                quantites = lots_df_filtered.groupby("type_lot")["quantite"].sum().tolist()
                colors = ['lightblue', 'lightgreen', 'lightpink']
                fig = go.Figure()
                n_points = 50
                r_base = 0.3
                for i, (type_lot, height) in enumerate(zip(types_lot, quantites)):
                    theta = np.linspace(0, 2 * np.pi, n_points)
                    x_base = r_base * np.cos(theta) + i
                    y_base = r_base * np.sin(theta)
                    z_base = np.zeros(n_points)
                    x_tip = np.full(n_points, i)
                    y_tip = np.zeros(n_points)
                    z_tip = np.full(n_points, height)
                    fig.add_trace(go.Surface(
                        x=np.array([x_base, x_tip]),
                        y=np.array([y_base, y_tip]),
                        z=np.array([z_base, z_tip]),
                        showscale=False,
                        colorscale=[[0, colors[i % len(colors)]], [1, colors[i % len(colors)]]],
                        name=type_lot,
                        opacity=0.85
                    ))
                    fig.add_trace(go.Scatter3d(
                        x=[i], y=[0], z=[height + 500],
                        text=[f"{type_lot}<br>{height} cartes"],
                        mode="text", showlegend=False
                    ))
                fig.update_layout(
                    title="Répartition des lots par type",
                    scene=dict(
                        xaxis=dict(title="Type de lot", tickvals=list(range(len(types_lot))), ticktext=types_lot),
                        yaxis=dict(title=""),
                        zaxis=dict(title="Quantité enregistrée")
                    ),
                    margin=dict(l=0, r=0, b=0, t=40),
                    scene_camera=dict(eye=dict(x=1.8, y=1.8, z=2.5)),
                    autosize=True
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            with st.container(border=True):
        # Graphique cylindres 3D par trimestre
                lots_df_filtered["Année"] = lots_df_filtered["date_enregistrement"].dt.year
                lots_df_filtered["Trimestre"] = lots_df_filtered["date_enregistrement"].dt.quarter
                agg = lots_df_filtered.groupby(["Année", "Trimestre"])["quantite"].sum().reset_index()
                agg["Label"] = agg.apply(lambda row: f"{row['Année']} - T{row['Trimestre']}", axis=1)
                fig = go.Figure()
                r = 0.4
                n_points = 50
                for i, row in agg.iterrows():
                    label = row["Label"]
                    height = row["quantite"]
                    theta = np.linspace(0, 2*np.pi, n_points)
                    x_circle = r * np.cos(theta) + i
                    y_circle = r * np.sin(theta)
                    z_base = np.zeros(n_points)
                    z_top = np.ones(n_points) * height
                    fig.add_trace(go.Surface(
                        x=np.array([x_circle, x_circle]),
                        y=np.array([y_circle, y_circle]),
                        z=np.array([z_base, z_top]),
                        showscale=False,
                        colorscale=[[0, 'lightblue'], [1, 'lightblue']],
                        name=label
                    ))
                    fig.add_trace(go.Scatter3d(
                        x=[i], y=[0], z=[height + 100],
                        text=[f"{label}<br>{int(height)} cartes"],
                        mode="text", showlegend=False
                    ))
                fig.update_layout(
                    title="Production trimestrielle",
                    scene=dict(
                        xaxis=dict(title="Trimestre", tickvals=list(range(len(agg))), ticktext=agg["Label"].tolist()),
                        yaxis=dict(title=""),
                        zaxis=dict(title="Cartes produites")
                    ),
                    margin=dict(l=0, r=0, b=0, t=40)
                )
                st.plotly_chart(fig, use_container_width=True)

        with st.container(border=True):
            lots_df_filtered["mois"] = lots_df_filtered["date_enregistrement"].dt.to_period("M").astype(str)
            evolution_lots = lots_df_filtered.groupby("mois")["quantite"].sum().reset_index()
            fig = px.line(evolution_lots, x="mois", y="quantite", markers=True,
                title="📈 Évolution mensuelle des lots enregistrés",
                labels={"mois": "Mois", "quantite": "Quantité totale"})
            st.plotly_chart(fig, use_container_width=True)
        st.divider()


        # KPIs sur le contrôle qualité
        st.subheader("Contrôle qualité")
        total_tests = controle_df_filtered["quantite_a_tester"].sum()
        nb_reussites = controle_df_filtered[controle_df_filtered["resultat"] == "Réussite"].shape[0]
        nb_echecs = controle_df_filtered[controle_df_filtered["resultat"] == "Échec"].shape[0]
        taux_reussite = (nb_reussites / (nb_reussites + nb_echecs)) * 100 if (nb_reussites + nb_echecs) > 0 else 0
        taux_echec = 100 - taux_reussite
        anomalies = controle_df_filtered[controle_df_filtered["remarque"].notna() & (controle_df_filtered["remarque"] != "")].shape[0]
        col1, col2, col3 = st.columns(3)
        col1.metric("Total cartes testées", total_tests, f"{total_tests} cartes testées", border=True)
        col2.metric("Taux de réussite", f"{taux_reussite:.2f}%", f"{taux_reussite:.2f}% de réussite", border=True)
        col3.metric("Taux d'échec", f"{taux_echec:.2f}%", f"{taux_echec:.2f}% d'échec", border=True)

        
        with st.container(border=True):
        # Graphique pyramides 3D par mois
            controle_df_filtered["Mois"] = controle_df_filtered["date_controle"].dt.to_period("M").astype(str)
            tests_mensuels = controle_df_filtered.groupby("Mois")["quantite_a_tester"].sum().reset_index()
            fig = go.Figure()
            base_size = 0.5
            for i, row in tests_mensuels.iterrows():
                label = row["Mois"]
                height = row["quantite_a_tester"]
                x_base = np.array([i - base_size, i + base_size, i + base_size, i - base_size])
                y_base = np.array([-base_size, -base_size, base_size, base_size])
                z_base = np.zeros(4)
                x_tip = i
                y_tip = 0
                z_tip = height
                for j in range(4):
                    x_face = [x_base[j], x_base[(j + 1) % 4], x_tip]
                    y_face = [y_base[j], y_base[(j + 1) % 4], y_tip]
                    z_face = [z_base[j], z_base[(j + 1) % 4], z_tip]
                    fig.add_trace(go.Mesh3d(x=x_face, y=y_face, z=z_face, color='lightcoral', opacity=0.9, showscale=False))
                    fig.add_trace(go.Scatter3d(x=[i], y=[0], z=[height + 100],
                                       text=[f"{label}<br>{int(height)} tests"], mode="text", showlegend=False))
            fig.update_layout(
                title="Nombre total de tests par mois",
                scene=dict(
                    xaxis=dict(title="Mois", tickvals=list(range(len(tests_mensuels))), ticktext=tests_mensuels["Mois"].tolist()),
                    yaxis=dict(title=""),
                    zaxis=dict(title="Nombre de tests")
                ),
                margin=dict(l=0, r=0, b=0, t=40),
                scene_camera=dict(eye=dict(x=1.8, y=1.8, z=2.5)),
                autosize=True
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        col3, col4 = st.columns([3,2])
        with col3:  

            with st.container(border=True):
            # Calculs
                total_enregistree = controle_df["quantite"].sum()
                total_testee = controle_df["quantite_a_tester"].sum()
                pourcentage = round((total_testee / total_enregistree) * 100, 2) if total_enregistree > 0 else 0
        # Données pour le diagramme en anneau
                donut_data = pd.DataFrame({
                    "Catégorie": ["Cartes testées", "Cartes non testées"],
                    "Quantité": [total_testee, total_enregistree - total_testee]
                })
    
                fig = px.pie(donut_data, names="Catégorie", values="Quantité", hole=0.5,title="Echantillonnage",
                    color_discrete_sequence=["#4682B4", "#27d636"])
                fig.update_traces(textinfo="label+percent")
                fig.update_layout(width=400, height=250, margin=dict(t=60, b=20, r=200, l=50), showlegend=False)

                st.plotly_chart(fig, use_container_width=True)

            with st.container(border=True):
            # Agrégation des données
                grouped = controle_df_filtered.groupby(["filiale", "type_carte"])["quantite_a_tester"].sum().reset_index()

        # Graphique interactif
                fig = px.bar(
                    grouped,
                    x="filiale",
                    y="quantite_a_tester",
                    color="type_carte",
                    title="Tests mensuels des cartes par filiale",
                    labels={"quantite_a_tester": "Cartes testées", "type_carte": "Type de carte"},
                    height=500
                )
                fig.update_traces(textposition="none")
                fig.update_layout(bargap=0.15, height=500, yaxis_title=None, showlegend=False)           
                fig.update_xaxes(showgrid=False)
                fig.update_yaxes(showgrid=False)
                fig.update_yaxes(visible=False)
                st.plotly_chart(fig, use_container_width=True)

        
        with col4:
            with st.container(border=True):
        # Graphique barres par filiale
                df_grouped = controle_df_filtered.groupby("filiale")["quantite_a_tester"].sum().reset_index()
                fig = px.bar(df_grouped, x="filiale", y="quantite_a_tester", text="quantite_a_tester",
                     title="Total des tests par filiale", labels={"filiale": "Filiale", "quantite_a_tester": "Tests"}, height=200)
                fig.update_traces(textposition="none")
                fig.update_layout(bargap=0.15, height=250, margin=dict(t=40, b=20), legend_title_text="Filiale", yaxis_title=None)           
                fig.update_xaxes(showgrid=False)
                fig.update_yaxes(showgrid=False)
                fig.update_yaxes(visible=False)

                st.plotly_chart(fig, use_container_width=True)

            with st.container(border=True):
        # Conversion des dates
                controle_df_filtered["date_controle"] = pd.to_datetime(controle_df_filtered["date_controle"], errors="coerce")
                controle_df_filtered["Mois"] = controle_df_filtered["date_controle"].dt.to_period("M").astype(str)

        # Graphique barres par type de carte
                fig = px.bar(controle_df_filtered["type_carte"].value_counts().reset_index(), x="type_carte", y="count",
                     labels={"count": "Type de carte", "type_carte": "Nombre de tests"},
                     title="Tests par type de carte")
                fig.update_traces(textposition="none")
                fig.update_layout(height=253, margin=dict(t=40, b=20), yaxis_title=None)           
                fig.update_xaxes(showgrid=False)
                fig.update_yaxes(showgrid=False)
                fig.update_yaxes(visible=False)
                st.plotly_chart(fig, use_container_width=True)

                    # 🔹 Récupération des données des expéditions
            expeditions_data = supabase.table("expedition").select("agence", "pays", "statut").execute().data
            expeditions_df = pd.DataFrame(expeditions_data)
        # ✅ 2. Préparation des données pour le graphique
            if not expeditions_df.empty:
        # Filtrer uniquement les expéditions avec statut "expédié"
                expeditions_filtre = expeditions_df[expeditions_df["statut"].str.lower() == "expédié"]
 
                with st.container(border=True):
        # Calculer la quantité par agence et filiale (nombre d'enregistrements)
                    repartition = expeditions_filtre.groupby(["agence", "pays"]).size().reset_index(name="quantite")

        # ✅ Graphique combiné : barres groupées par agence et filiale
                    fig = px.bar(
                        repartition,
                        x="agence",
                        y="quantite",
                        color="pays",
                        barmode="group",
                        title="Expéditions par agence",
                        labels={"agence": "Agence", "quantite": "Nombre d'expéditions", "pays": "Filiale"}
                    )
                    fig.update_layout(height=200, margin=dict(t=40, b=20), legend_title_text="Filiale", showlegend=False, yaxis_title=None)
                    fig.update_traces(textposition="none")
                    st.plotly_chart(fig, use_container_width=True)

            
    # 🔍 Récupération des expéditions
    try:
        df = pd.DataFrame(supabase.table("expedition").select("statut, agence").execute().data)
    except Exception as e:
        st.error(f"Erreur lors de la récupération des expéditions : {e}")
        df = pd.DataFrame()

    if df.empty:
        st.warning("Aucune expédition enregistrée.")
    else:
        st.divider()
        st.subheader("Répartition des expéditions")

        agence_counts = df["agence"].value_counts().reset_index()
        agence_counts.columns = ["Agence", "Nombre"]
        cols = st.columns(len(agence_counts), border=True)
        for i, row in agence_counts.iterrows():
            cols[i].metric(f"{row['Agence']}", row["Nombre"], f"{row["Nombre"]} expéditions")   
        st.divider()     

        with st.container(border=True):
        # Graphique prévision linéaire
            monthly_tests = controle_df_filtered.groupby("Mois")["quantite_a_tester"].sum().reset_index()
            monthly_tests["Mois_Num"] = pd.to_datetime(monthly_tests["Mois"]).map(lambda x: x.toordinal())
            X = monthly_tests[["Mois_Num"]]
            y = monthly_tests["quantite_a_tester"]
            model = LinearRegression()
            model.fit(X, y)
            last_month = pd.to_datetime(monthly_tests["Mois"]).max()
            future_months = [last_month + pd.DateOffset(months=i) for i in range(1, 7)]
            future_ordinals = [m.toordinal() for m in future_months]
            future_preds = model.predict(np.array(future_ordinals).reshape(-1, 1))
            future_df = pd.DataFrame({
                "Mois": [m.strftime("%Y-%m") for m in future_months],
                "quantite_a_tester": future_preds,
                "Source": "Prévision"
            })
            monthly_tests["Source"] = "Historique"
            monthly_tests = monthly_tests[["Mois", "quantite_a_tester", "Source"]]
            combined_df = pd.concat([monthly_tests, future_df], ignore_index=True)
            fig = px.line(combined_df, x="Mois", y="quantite_a_tester", color="Source", markers=True,
                    title="Prévision des tests mensuels", height=300, labels={"quantite_a_tester": "Nombre de tests", "Mois": "Mois"})
            fig.update_layout(xaxis_title="Mois", yaxis_title="Nombre de tests")
            st.plotly_chart(fig, use_container_width=True)

        with st.container(border=True):
        # Graphique courbe 3D par jour de la semaine
            controle_df_filtered["date_controle"] = pd.to_datetime(controle_df_filtered["date_controle"], errors="coerce")
            controle_df_filtered["Jour_Semaine"] = controle_df_filtered["date_controle"].dt.day_name()
            controle_df_filtered["Jour_Semaine"] = controle_df_filtered["Jour_Semaine"].map({'Monday': 'Lundi', 'Tuesday': 'Mardi', 'Wednesday': 'Mercredi', 'Thursday': 'Jeudi', 'Friday': 'Vendredi', 'Saturday': 'Samedi', 'Sunday': 'Dimanche'})
            tests_par_jour = controle_df_filtered.groupby("Jour_Semaine")["quantite_a_tester"].sum().reset_index()
            jours_ordonne = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"]
            tests_par_jour["Jour_Semaine"] = pd.Categorical(tests_par_jour["Jour_Semaine"], categories=jours_ordonne, ordered=True)
            tests_par_jour = tests_par_jour.sort_values("Jour_Semaine")
            x = list(range(len(tests_par_jour)))
            y = [0] * len(tests_par_jour)
            z = tests_par_jour["quantite_a_tester"].tolist()
            labels = tests_par_jour["Jour_Semaine"].tolist()
            fig = go.Figure(data=[
                go.Scatter3d(x=x, y=y, z=z, mode='lines+markers+text',
                    text=[f"{jour}<br>{val} tests" for jour, val in zip(labels, z)],
                    line=dict(color='royalblue', width=4), marker=dict(size=6))
            ])
                    
            fig.update_layout(
               title="📈 Total des tests journaliers suivant le jour de la semaine",
               scene=dict(
                  xaxis=dict(title="Jour", tickvals=x, ticktext=labels),
                  yaxis=dict(title=""),
                  zaxis=dict(title="Nombre de tests")
               ),
               margin=dict(l=0, r=0, b=0, t=40),
               scene_camera=dict(eye=dict(x=1.5, y=1.5, z=1.5))
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with st.container(border=True):
            controle_df_filtered["semaine"] = controle_df_filtered["date_controle"].dt.to_period("W").astype(str)
            evolution_tests = controle_df_filtered.groupby("semaine")["quantite_a_tester"].sum().reset_index()
            fig = px.bar(evolution_tests, x="semaine", y="quantite_a_tester",
                     title="Évolution hebdomadaire des tests qualité",
                     labels={"semaine": "Semaine", "quantite_a_tester": "Nombre total de tests"},
                     height=400,
                     text="quantite_a_tester")
            fig.update_traces(marker_color="mediumseagreen", textposition="none")
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
    
elif menu == "➕ Enregistrement des lots":
    enregistrer_lot()


elif menu == "📋 Visualisation des lots":
    from supabase import create_client
    import pandas as pd

    # Connexion à Supabase
    url = st.secrets["supabase_url"]
    key = st.secrets["supabase_key"]
    supabase = create_client(url, key)

    st.markdown("## 📋 Visualisation des lots")
    st.divider()

    
# Pagination pour récupérer tous les lots
    page_size = 1000
    offset = 0
    all_lots = []

    while True:
        response = supabase.table("lots") \
            .select("*") \
            .range(offset, offset + page_size - 1) \
            .execute()
        
        if not response.data:
            break  # Stop si plus de données
        all_lots.extend(response.data)
        offset += page_size

    lots_data = all_lots

    if lots_data:
        df = pd.DataFrame(lots_data)
        df["date_enregistrement"] = pd.to_datetime(df["date_enregistrement"], errors="coerce")

        # Filtres latéraux
        st.sidebar.header("🔍 Filtres")
        min_date = df["date_enregistrement"].min().date()
        max_date = df["date_enregistrement"].max().date()
        date_range = st.sidebar.date_input("Date d'enregistrement", [min_date, max_date])

        filiales = df["filiale"].dropna().unique().tolist()
        filiale_selection = st.sidebar.multiselect("Filiale", filiales, default=filiales)

        types_lot = df["type_lot"].dropna().unique().tolist()
        type_selection = st.sidebar.multiselect("Type de lot", types_lot, default=types_lot)

        # Application des filtres
        df_filtered = df[
            (df["date_enregistrement"].dt.date >= date_range[0]) &
            (df["date_enregistrement"].dt.date <= date_range[1]) &
            (df["filiale"].isin(filiale_selection)) &
            (df["type_lot"].isin(type_selection))
        ]
                
# --- KPIs : Quantité des cartes par type de lot ---
        with st.container(border=True):
            st.subheader("Indicateurs de lots enregistrés")

            if df_filtered.empty:
                st.info("Aucun lot ne correspond aux filtres sélectionnés.")
            else:
    # Agréger les quantités par type de lot
                grouped_types = (
                    df_filtered.groupby("type_lot")["quantite"]
                    .sum()
                    .reset_index()
                )

    # S'assurer d'avoir toujours les 3 types affichés, même si un type est absent dans les filtres
                types_cibles = ["Ordinaire", "Émission instantanée", "Renouvellement"]
                quantites_dict = {t: 0 for t in types_cibles}
                quantites_dict.update(dict(zip(grouped_types["type_lot"], grouped_types["quantite"])))

    # Petit formatteur pour les valeurs (12 345)
                def fmt(n):
                    return f"{int(n):,}".replace(",", " ")

    # Affichage des métriques (3 colonnes)
                col1, col2 = st.columns(2)

                col1.metric(
                    label="🟦 Ordinaire",
                    value=fmt(quantites_dict["Ordinaire"]), 
                    delta=f"{fmt(quantites_dict["Ordinaire"])} cartes type : ordinaire",
                    border=True
                )
                col2.metric(
                    label="🟧 Émission instantanée",
                    value=fmt(quantites_dict["Émission instantanée"]),
                    delta=f"{fmt(quantites_dict["Émission instantanée"])} cartes type : émission instantanée",
                    border=True
                )

                col3, col4 = st.columns(2)

                col3.metric(
                    label="🟨 Renouvellement",
                    value=fmt(quantites_dict["Renouvellement"]),
                    delta=f"{fmt(quantites_dict["Renouvellement"])} cartes type : renouvellement",
                    border=True
                )
                col4.metric(
                    label="🔢 Total cartes",
                    value=fmt(df_filtered["quantite"].sum()),
                    delta=f"{fmt(df_filtered["quantite"].sum())} cartes enregistrées",
                    border=True
                )
        st.dataframe(df_filtered, use_container_width=True)
        st.divider()

# -- État de navigation local à la gestion des lots --
        if "lot_action" not in st.session_state:
            st.session_state["lot_action"] = None   # "add" | "edit" | "delete"
        if "lot_id_cible" not in st.session_state:
            st.session_state["lot_id_cible"] = None

        with st.container(border=True):
            st.markdown("### 🛠️ Effectuer une action sur les lots enregistrés")
            ModifierL, SupprimerL = st.columns(2)

    # ---------------------- ✏️ MODIFIER ----------------------
            if ModifierL.button("Modifier Lot", use_container_width=True):
                st.session_state["lot_action"] = "edit"
                st.session_state["lot_id_cible"] = None
                st.rerun()

    # ---------------------- 🗑️ SUPPRIMER ----------------------
            if SupprimerL.button("Supprimer Lot", use_container_width=True):
                st.session_state["lot_action"] = "delete"
                st.session_state["lot_id_cible"] = None
                st.rerun()

# === PANNEAUX D'ACTIONS SELON LE CONTEXTE ===

# ---------- ✏️ MODIFIER ----------
            elif st.session_state["lot_action"] == "edit":
                st.markdown("#### ✏️ Modifier un lot existant")

                if df_filtered.empty:
                    st.info("Aucun lot à modifier avec les filtres actuels.")
                    st.button("❌ Fermer", on_click=lambda: st.session_state.update({"lot_action": None, "lot_id_cible": None}))
                else:
        # Sélection de la cible parmi le tableau filtré (cohérent avec ta pratique)
                    options = {
                        f"{int(row['id'])} - {row['nom_lot']}": int(row["id"])
                            for _, row in df_filtered.iterrows()
                    }
                    sel_label = st.selectbox("Sélectionnez le lot à modifier", list(options.keys()))
                    lot_id = options[sel_label]

        # Charge la ligne complète du lot dans la table
                    lot_data = df[df["id"] == lot_id].iloc[0] if not df.empty else None
                    if lot_data is None:
                        st.warning("Impossible de charger le lot sélectionné.")
                        st.button("❌ Fermer", on_click=lambda: st.session_state.update({"lot_action": None, "lot_id_cible": None}))
                    else:
                        with st.form("form_modification_vs"):
                            col1, col2 = st.columns(2)
                            with col1:
                                new_nom = st.text_input("Nom du lot", value=lot_data["nom_lot"])
                                new_type = st.selectbox(
                                    "Type de lot",
                                    ["Ordinaire", "Émission instantanée", "Renouvellement"],
                                    index=["Ordinaire", "Émission instantanée", "Renouvellement"].index(lot_data["type_lot"])
                                )
                                new_quantite = st.number_input("Quantité totale", min_value=1, value=int(lot_data["quantite"]))
                                new_date_prod = st.date_input("Date de production", value=pd.to_datetime(lot_data["date_production"]).date())
                            with col2:
                                new_date_enr = st.date_input("Date d'enregistrement", value=pd.to_datetime(lot_data["date_enregistrement"]).date())
                                new_filiale = st.selectbox(
                                    "Filiale",
                                    ["Burkina Faso", "Mali", "Niger", "Côte d'Ivoire", "Sénégal", "Bénin", "Togo", "Guinée Bissau", "Guinée Conakry"],
                                       index=["Burkina Faso", "Mali", "Niger", "Côte d'Ivoire", "Sénégal", "Bénin", "Togo", "Guinée Bissau", "Guinée Conakry"].index(lot_data["filiale"])
                                    )
                                new_impression = st.radio(
                                    "Impression de PIN ?",
                                    ["Oui", "Non"],
                                    index=["Oui", "Non"].index(lot_data["impression_pin"])
                                )
                                default_pin = int(lot_data["nombre_pin"]) if lot_data["impression_pin"] == "Oui" else 1
                                new_nombre_pin = st.number_input("Nombre de PIN", min_value=1, value=default_pin) if new_impression == "Oui" else 0

                # Recalcule le nombre de cartes à tester (même règle)
                                new_cartes_test = math.ceil(new_quantite / 50)
                                submit_mod = st.form_submit_button("✅ Enregistrer les modifications")
                                if submit_mod:
                                    supabase.table("lots").update({
                                        "nom_lot": new_nom,
                                        "type_lot": new_type,
                                        "quantite": int(new_quantite),
                                        "date_production": str(new_date_prod),
                                        "date_enregistrement": str(new_date_enr),
                                        "filiale": new_filiale,
                                        "impression_pin": new_impression,
                                        "nombre_pin": int(new_nombre_pin) if new_impression == "Oui" else 0,
                                        "cartes_a_tester": int(new_cartes_test)
                                    }).eq("id", lot_id).execute()
                                    st.success("✅ Lot modifié avec succès.")
                                    st.session_state["lot_action"] = None
                                    st.session_state["lot_id_cible"] = None
                                    st.rerun()
                    st.button("❌ Fermer", on_click=lambda: st.session_state.update({"lot_action": None, "lot_id_cible": None}))

# ---------- 🗑️ SUPPRIMER ----------
            elif st.session_state["lot_action"] == "delete":
                st.markdown("#### 🗑️ Supprimer un lot")

                if df_filtered.empty:
                    st.info("Aucun lot à supprimer avec les filtres actuels.")
                    st.button("❌ Fermer", on_click=lambda: st.session_state.update({"lot_action": None, "lot_id_cible": None}))
                else:
                    options = {
                        f"{int(row['id'])} - {row['nom_lot']}": int(row["id"])
                        for _, row in df_filtered.iterrows()
                    }
                    sel_label = st.selectbox("Sélectionnez le lot à supprimer", list(options.keys()))
                    lot_id = options[sel_label]

        # Affiche un récap succinct
                    lot_data = df[df["id"] == lot_id].iloc[0] if not df.empty else None
                    if lot_data is not None:
                        st.write(f"📦 **{lot_data['nom_lot']}** — {lot_data['filiale']} — {lot_data['type_lot']} — {int(lot_data['quantite'])} cartes")

                    colA, colB = st.columns(2)
                    with colA:
                        if st.button("🗑️ Supprimer définitivement", type="primary", use_container_width=True):
                            supabase.table("lots").delete().eq("id", lot_id).execute()
                            st.warning("🗑️ Lot supprimé.")
                            st.session_state["lot_action"] = None
                            st.session_state["lot_id_cible"] = None
                            st.rerun()
                    with colB:
                        st.button("❌ Annuler", use_container_width=True,
                        on_click=lambda: st.session_state.update({"lot_action": None, "lot_id_cible": None}))
                        
    else:
        st.warning("Aucun lot enregistré dans la base de données Supabase.")


elif menu == "✏️ Modification/Suppression Lot":
    from supabase import create_client
    import pandas as pd
    import math

    # Connexion à Supabase
    url = st.secrets["supabase_url"]
    key = st.secrets["supabase_key"]
    supabase = create_client(url, key)

    st.markdown("## ✏️ Modifier ou supprimer un lot")

    # Récupération des lots
    response = supabase.table("lots").select("*").execute()
    lots_data = response.data

    if lots_data:
        df = pd.DataFrame(lots_data)
        df["label"] = df["id"].astype(str) + " - " + df["nom_lot"]
        selected_label = st.selectbox("Sélectionner un lot à modifier ou supprimer", df["label"])
        selected_id = int(selected_label.split(" - ")[0])
        lot_data = df[df["id"] == selected_id].iloc[0]

        with st.form("form_modification"):
            col1, col2 = st.columns(2)
            with col1:
                new_nom = st.text_input("Nom du lot", value=lot_data["nom_lot"])
                new_type = st.selectbox("Type de lot", ["Ordinaire", "Émission instantanée", "Renouvellement"], index=["Ordinaire", "Émission instantanée", "Renouvellement"].index(lot_data["type_lot"]))
                new_quantite = st.number_input("Quantité totale", min_value=1, value=lot_data["quantite"])
                new_date_prod = st.date_input("Date de production", value=pd.to_datetime(lot_data["date_production"]).date())
            with col2:
                new_date_enr = st.date_input("Date d'enregistrement", value=pd.to_datetime(lot_data["date_enregistrement"]).date())
                new_filiale = st.selectbox("Filiale", ["Burkina Faso", "Mali", "Niger", "Côte d'Ivoire", "Sénégal", "Bénin", "Togo", "Guinée Bissau", "Guinée Conakry"], index=["Burkina Faso", "Mali", "Niger", "Côte d'Ivoire", "Sénégal", "Bénin", "Togo", "Guinée Bissau", "Guinée Conakry"].index(lot_data["filiale"]))
                new_impression = st.radio("Impression de PIN ?", ["Oui", "Non"], index=["Oui", "Non"].index(lot_data["impression_pin"]))
                default_pin = lot_data["nombre_pin"] if lot_data["impression_pin"] == "Oui" else 1
                new_nombre_pin = st.number_input("Nombre de PIN", min_value=1, value=default_pin) if new_impression == "Oui" else 0

            new_cartes_test = math.ceil(new_quantite / 50)
            mod_submit = st.form_submit_button("✅ Modifier le lot")

            if mod_submit:
                supabase.table("lots").update({
                    "nom_lot": new_nom,
                    "type_lot": new_type,
                    "quantite": new_quantite,
                    "date_production": str(new_date_prod),
                    "date_enregistrement": str(new_date_enr),
                    "filiale": new_filiale,
                    "impression_pin": new_impression,
                    "nombre_pin": new_nombre_pin,
                    "cartes_a_tester": new_cartes_test
                }).eq("id", selected_id).execute()
                st.success("✅ Lot modifié avec succès.")
                st.rerun()

        if st.button("🗑️ Supprimer ce lot"):
            supabase.table("lots").delete().eq("id", selected_id).execute()
            st.warning("🗑️ Lot supprimé avec succès.")
            st.rerun()
    else:
        st.warning("Aucun lot disponible dans Supabase.")


elif menu == "🧪 Contrôle qualité":
    from supabase import create_client
    import math
    from datetime import date

    # Connexion à Supabase
    url = st.secrets["supabase_url"]
    key = st.secrets["supabase_key"]
    supabase = create_client(url, key)

    st.markdown("## 🧪 Contrôle qualité")
    st.divider()

    # Récupération des lots
    response = supabase.table("lots").select("id", "nom_lot").execute()
    lots = response.data
    if not lots:
        st.warning("Aucun lot disponible.")
        st.stop()

    # 🔍 Récupérer tous les lots
    lots_response = supabase.table("lots").select("id", "nom_lot").execute()
    lots = lots_response.data
    
    # Pagination pour récupérer tous les lot_id contrôlés
    page_size = 1000
    offset = 0
    lots_controles = []

    while True:
        controle_response = supabase.table("controle_qualite") \
            .select("lot_id") \
            .range(offset, offset + page_size - 1) \
            .execute()
    
        if not controle_response.data:
            break
        lots_controles.extend([row["lot_id"] for row in controle_response.data])
        offset += page_size

    # ✅ Filtrer les lots non contrôlés
    lots_non_controles = [lot for lot in lots if lot["id"] not in lots_controles]

    # 🛑 Si tous les lots sont déjà contrôlés
    if not lots_non_controles:
        st.warning("✅ Tous les lots ont déjà été contrôlés.")
        st.stop()

    # 🎯 Affichage de la liste filtrée
    lot_dict = {f"{lot['id']} - {lot['nom_lot']}": lot["id"] for lot in lots_non_controles}
    selected_lot = st.selectbox("Sélectionnez un lot :", list(lot_dict.keys()))
    lot_id = lot_dict[selected_lot]

    # Types de cartes
    types_cartes = [
        "challenge", "open", "challenge plus", "access", "visa leader",
        "visa gold encoche", "visa infinite encoche", "visa gold premier",
        "visa infinite premier", "wadia challenge", "wadia open", "wadia challenge plus"
    ]
    types_selectionnes = st.multiselect("Types de cartes dans le lot :", types_cartes)

    quantites = {}
    quantites_a_tester = {}
    total_a_tester = 0

    for type_carte in types_selectionnes:
        qte = st.number_input(f"Quantité pour {type_carte} :", min_value=1, step=1, key=f"qte_{type_carte}")
        quantites[type_carte] = qte

        # Calcul des cartes à tester
        if len(types_selectionnes) == 1:
            test = math.ceil(qte / 50)
        else:
            if qte <= 50:
                test = 1
            elif qte <= 100:
                test = 2
            else:
                test = 3
        quantites_a_tester[type_carte] = test
        total_a_tester += test

    remarque = st.text_area("Remarques / Anomalies", value="RAS")
    resultat_test = st.radio("Résultat du test :", ["Réussite", "Échec"], key="resultat_test")
    
    if st.button("Enregistrer le contrôle qualité"):             
            for type_carte in types_selectionnes:
                last_id_data = supabase.table("controle_qualite").select("id").order("id", desc=True).limit(1).execute().data
                next_id = (last_id_data[0]["id"] + 1) if last_id_data else 1
                supabase.table("controle_qualite").insert({
                    "id": next_id,
                    "lot_id": lot_id,
                    "type_carte": type_carte,
                    "quantite": quantites[type_carte],
                    "quantite_a_tester": quantites_a_tester[type_carte],
                    "date_controle": str(date.today()),
                    "remarque": remarque,
                    "resultat": resultat_test
                }).execute()
            st.success("✅ Contrôle qualité enregistré avec succès.")
            st.rerun()

    # Résumé
    if types_selectionnes:
        st.subheader("📋 Résumé des tests")
        for type_carte in types_selectionnes:
            st.write(f"{type_carte} : {quantites[type_carte]} cartes → {quantites_a_tester[type_carte]} à tester")
        st.write(f"🔢 Total des cartes à tester : {total_a_tester}")


elif menu == "🗂 Inventaire des tests":
    st.markdown("## 🗂 Inventaire du contrôle qualité")

    # Pagination pour récupérer toutes les lignes
    page_size = 1000
    offset = 0
    all_data = []

    while True:
        response = supabase.table("controle_qualite") \
            .select("id, date_controle, type_carte, quantite, quantite_a_tester, remarque, resultat, lot_id") \
            .range(offset, offset + page_size - 1) \
            .execute()
    
        if not response.data:
            break  # Stop si plus de données
        all_data.extend(response.data)
        offset += page_size

    controle_data = all_data

    # Récupération des noms de lots et filiales
    lots_response = supabase.table("lots").select("id, nom_lot, filiale").execute()
    lots_data = {lot["id"]: (lot["nom_lot"], lot["filiale"]) for lot in lots_response.data}

    # Fusion des données
    for row in controle_data:
        lot_info = lots_data.get(row["lot_id"], ("Inconnu", ""))
        row["nom_lot"] = lot_info[0]
        row["filiale"] = lot_info[1]

    df = pd.DataFrame(controle_data)
    
    mois_en_fr = {
            'January': 'Janvier', 'February': 'Février', 'March': 'Mars', 'April': 'Avril',
            'May': 'Mai', 'June': 'Juin', 'July': 'Juillet', 'August': 'Août',
            'September': 'Septembre', 'October': 'Octobre', 'November': 'Novembre', 'December': 'Décembre'
        }
    semaine_en_fr = {
            'Monday': 'Lundi', 'Tuesday': 'Mardi', 'Wednesday': 'Mercredi', 'Thursday': 'Jeudi',
            'Friday': 'Vendredi', 'Saturday': 'Samedi', 'Sunday': 'Dimanche'
        }

    if df.empty:
        st.warning("Aucun test de contrôle qualité enregistré.")
    else:
        df["date_controle"] = pd.to_datetime(df["date_controle"])
        df["Année"] = df["date_controle"].dt.year
        df["Mois"] = df["date_controle"].dt.month_name().map(mois_en_fr)
        df["Trimestre"] = df["date_controle"].dt.quarter
        df["Semaine"] = df["date_controle"].dt.isocalendar().week
        df["Jour"] = df["date_controle"].dt.day
        df["Jour_Semaine"] = df["date_controle"].dt.day_name().map(semaine_en_fr)

        # Filtres
        st.sidebar.header("🔎 Filtres Inventaire")
        date_min = df["date_controle"].min().date()
        date_max = df["date_controle"].max().date()
        date_range = st.sidebar.date_input("Période de contrôle", [date_min, date_max])
        lots = df["nom_lot"].unique().tolist()
        lot_selection = st.sidebar.multiselect("Nom du lot", lots, default=lots)
        filiales = df["filiale"].unique().tolist()
        filiale_selection = st.sidebar.multiselect("Filiale", filiales, default=filiales)
        resultats = df["resultat"].unique().tolist()
        resultat_selection = st.sidebar.multiselect("Résultat", resultats, default=resultats)

        df_filtered = df[
            (df["date_controle"].dt.date >= date_range[0]) &
            (df["date_controle"].dt.date <= date_range[1]) &
            (df["nom_lot"].isin(lot_selection)) &
            (df["filiale"].isin(filiale_selection)) &
            (df["resultat"].isin(resultat_selection))
        ]

        st.dataframe(df_filtered, use_container_width=True)

        # KPIs
        st.subheader("📊 Résumé des tests")
        total_testees = df_filtered["quantite_a_tester"].sum()
        nb_reussites = df_filtered[df_filtered["resultat"] == "Réussite"].shape[0]
        nb_echecs = df_filtered[df_filtered["resultat"] == "Échec"].shape[0]
        col1, col2, col3 = st.columns(3)
        col1.metric("Total de cartes testées", total_testees)
        col2.metric("Nombre de réussite", nb_reussites)
        col3.metric("Nombre d'échecs", nb_echecs)

        # Gestion des tests enregistrés
        st.subheader("🛠️ Gestion des tests enregistrés")
        for index, row in df_filtered.iterrows():
            col1, col2, col3 = st.columns([4, 1, 1])
            with col1:
                st.write(f"""
                📄 **{row['nom_lot']}**
                {row['filiale']}
                {row['type_carte']}
                {row['quantite']} cartes
                {row['quantite_a_tester']} à tester
                {row['resultat']}
                {row['remarque']}
                """)

            with col2:
                if st.button("✏️ Modifier", key=f"mod_{index}"):
                    st.session_state["mod_test_id"] = row["id"]
                    st.rerun()

            if st.session_state.get("mod_test_id") == row["id"]:
                with st.form(f"form_mod_{index}"):
                    new_type = st.text_input("Type de carte", value=row["type_carte"])
                    new_quantite = st.number_input("Nouvelle quantité", value=row["quantite"], min_value=1)
                    new_quantite_test = st.number_input("Nouvelle quantité à tester", value=row["quantite_a_tester"], min_value=1)
                    new_resultat = st.selectbox("Résultat", ["Réussite", "Échec"], index=["Réussite", "Échec"].index(row["resultat"]))
                    new_remarque = st.text_area("Remarque", value=row["remarque"])
                    submit_mod = st.form_submit_button("✅ Enregistrer les modifications")
                    if submit_mod:
                        supabase.table("controle_qualite").update({
                            "type_carte": new_type,
                            "quantite": new_quantite,
                            "quantite_a_tester": new_quantite_test,
                            "resultat": new_resultat,
                            "remarque": new_remarque
                        }).eq("id", row["id"]).execute()
                        st.success("✅ Test modifié avec succès.")
                        st.session_state["mod_test_id"] = None
                        st.rerun()

            with col3:
                if st.button("🗑️ Supprimer", key=f"del_{index}"):
                    supabase.table("controle_qualite").delete().eq("id", row["id"]).execute()
                    st.warning("🗑️ Test supprimé.")
                    st.rerun()


# Bloc Conditionnement des cartes
if menu == "📦 Conditionnement des cartes":
    st.markdown("## 📦 Conditionnement des cartes")

    # Sélection de la date
    selected_date = st.date_input("📅 Sélectionnez une date", value=date.today())

    # Récupération des lots enregistrés à cette date
    response = supabase.table("lots").select("id, nom_lot, type_lot, quantite, filiale, date_enregistrement").eq("date_enregistrement", str(selected_date)).execute()
    lots_data = response.data

    if not lots_data:
        st.warning("Aucune filiale n'a enregistré de lots à cette date.")
    else:
        df_lots = pd.DataFrame(lots_data)
        filiales = df_lots["filiale"].unique().tolist()
        selected_filiale = st.selectbox("🏢 Sélectionnez une filiale", filiales)

        # Filtrer les lots par filiale
        df_filiale = df_lots[df_lots["filiale"] == selected_filiale]

        st.subheader("📋 Lots enregistrés")
        st.dataframe(df_filiale[["nom_lot", "type_lot", "quantite"]], use_container_width=True)

        # Regroupement par type de lot
        regroupement = {}
        for _, row in df_filiale.iterrows():
            regroupement.setdefault(row["type_lot"], []).append((row["id"], row["nom_lot"], row["quantite"]))
        tableau_conditionnement = []

        for type_lot, lots_groupes in regroupement.items():
            st.markdown(f"### 🎯 Type de lot : {type_lot}")
            total = sum(q for _, _, q in lots_groupes)
            st.write(f"Total cartes : {total}")

            
# Récupération des cartes VIP enregistrées
            vip_response = supabase.table("controle_qualite").select("type_carte, quantite").in_("lot_id", [lot[0] for lot in lots_groupes]).execute()
            vip_data = vip_response.data if vip_response.data else []

            qte_gold = sum(row["quantite"] for row in vip_data if "gold" in row["type_carte"].lower())
            qte_infinite = sum(row["quantite"] for row in vip_data if "infinite" in row["type_carte"].lower())
            total_vip = qte_gold + qte_infinite
            packs_vip = total_vip  # 1 carte = 1 pack

            
            st.markdown("#### 🏅 Spécifications VIP")
            st.write(f"Quantité VIP : {total_vip} (Gold: {qte_gold}, Infinite: {qte_infinite})")

            st.info(f"📦 Packs VIP à conditionner : {packs_vip}")
            st.write("📤 Emballage Packs : Enveloppe(s) grand format")

            # Calcul des paquets classiques
            def calcul_paquets_conditionnement(quantite_totale, filiale):
                paquets = []
                capacite = 249 if filiale.lower() == "sénégal" else 500
                reste = quantite_totale
                while reste > 0:
                    if reste <= 150:
                        type_emballage = "Enveloppe"
                        cartes_emballees = reste
                    else:
                        type_emballage = "Paquet"
                        cartes_emballees = min(capacite, reste)
                    paquets.append((type_emballage, cartes_emballees))
                    reste -= cartes_emballees
                return paquets

            paquets = calcul_paquets_conditionnement(total, selected_filiale)

            for i, (type_emballage, cartes_emballees) in enumerate(paquets, 1):
                st.success(f"📦 Conditionnement du lot : {cartes_emballees} cartes pour {type_emballage} ")         
                import uuid
                unique_id = str(uuid.uuid4())[:8]  # Génère un identifiant court unique
                remarque = st.text_input(
                    f"📝 Remarque sur le conditionnement ({type_emballage})",
                    value="RAS",
                    key=f"remarque_{i}_{type_emballage}_{unique_id}"
                )
                
                tableau_conditionnement.append({
                    "Nom du lot": ", ".join([lot[1] for lot in lots_groupes]),
                    "Type de lot": type_lot,
                    "Filiale": selected_filiale,
                    "Quantité": cartes_emballees,
                    "Quantité VIP": total_vip,
                    "Packs VIP": packs_vip,
                    "Conditionnement": type_emballage,
                    "Remarque": remarque
                })
                
        # Affichage du tableau récapitulatif
        st.subheader("📋 Tableau de conditionnement")
        df_conditionnement = pd.DataFrame(tableau_conditionnement)
        st.dataframe(df_conditionnement, use_container_width=True)

        # ✅ Enregistrement dans Supabase
        if st.button("✅ Enregistrer le conditionnement"):
            for _, row in df_conditionnement.iterrows():
                nom_lot = row.get("Nom du lot")
                type_emballage = row.get("Conditionnement")
                filiale = row.get("Filiale")

        # 🔍 Vérification des doublons
                doublon = supabase.table("conditionnement").select("id")\
                .eq("nom_lot", nom_lot)\
                .eq("date_conditionnement", str(selected_date))\
                .eq("type_emballage", type_emballage)\
                .eq("filiale", filiale).execute().data

                if doublon:
                    st.warning(f"⚠️ Le conditionnement du lot {nom_lot} ({type_emballage}) pour la filiale {filiale} à la date {selected_date} existe déjà.")
                else:
            # ✅ Enregistrement si pas de doublon
                    supabase.table("conditionnement").insert({
                        "lot_id": None,
                        "type_lot": row["Type de lot"],
                        "filiale": filiale,
                        "type_emballage": type_emballage,
                        "nombre_cartes": row["Quantité"],
                        "date_conditionnement": str(selected_date),
                        "operateur": st.session_state["utilisateur"],
                        "remarque": row["Remarque"],
                        "packs": row["Packs VIP"],
                        "nom_lot": nom_lot
                    }).execute()
                    st.success("✅ Conditionnement enregistré avec succès.")

#Inventaire de conditionnements
elif menu == "🗂 Inventaire des conditionnements":
    st.markdown("## 🗂 Inventaire des conditionnements")

# Pagination pour récupérer tous les conditionnements
    page_size = 1000
    offset = 0
    all_conditionnements = []

    while True:
        response = supabase.table("conditionnement") \
            .select("*") \
            .range(offset, offset + page_size - 1) \
            .execute()
        
        if not response.data:
            break  # Stop si plus de données
        all_conditionnements.extend(response.data)
        offset += page_size

    data = all_conditionnements

    if not data:
        st.warning("Aucun conditionnement enregistré.")
    else:
        df = pd.DataFrame(data)
        df["date_conditionnement"] = pd.to_datetime(df["date_conditionnement"], errors="coerce")

        # Filtres
        st.sidebar.header("🔍 Filtres")
        date_min = df["date_conditionnement"].min().date()
        date_max = df["date_conditionnement"].max().date()
        date_range = st.sidebar.date_input("📅 Période", [date_min, date_max])

        filiales = df["filiale"].dropna().unique().tolist()
        filiale_selection = st.sidebar.multiselect("🏢 Filiale", filiales, default=filiales)

        types_lot = df["type_lot"].dropna().unique().tolist()
        type_selection = st.sidebar.multiselect("🎯 Type de lot", types_lot, default=types_lot)

        emballages = df["type_emballage"].dropna().unique().tolist()
        emballage_selection = st.sidebar.multiselect("📦 Type d'emballage", emballages, default=emballages)

        operateurs = df["operateur"].dropna().unique().tolist()
        operateur_selection = st.sidebar.multiselect("👤 Opérateur", operateurs, default=operateurs)

        # Application des filtres
        df_filtered = df[
            (df["date_conditionnement"].dt.date >= date_range[0]) &
            (df["date_conditionnement"].dt.date <= date_range[1]) &
            (df["filiale"].isin(filiale_selection)) &
            (df["type_lot"].isin(type_selection)) &
            (df["type_emballage"].isin(emballage_selection)) &
            (df["operateur"].isin(operateur_selection))
        ]

        st.subheader("📋 Tableau des conditionnements")
        colonnes = ["id", "nom_lot", "type_lot", "filiale", "type_emballage", "nombre_cartes", "packs", "remarque", "operateur", "date_conditionnement"]
        st.dataframe(df_filtered[colonnes], use_container_width=True)

        # Bouton global pour tout effacer
        if st.button("🧹 Effacer tout le tableau"):
            supabase.table("conditionnement").delete().execute()
            st.warning("🧹 Tous les conditionnements ont été supprimés.")
            st.rerun()

        st.subheader("⚙️ Actions sur conditionnement")
        for index, row in df_filtered.iterrows():
            col1, col2, col3 = st.columns([6, 1, 1])
            with col1:
                st.write(f"🆔 {row['id']} — {row['nom_lot']} ({row['filiale']}) — {row['type_emballage']} — {row['nombre_cartes']} cartes")
            with col2:
                if st.button("✏️ Modifier", key=f"mod_{row['id']}"):
                    st.session_state["mod_conditionnement_id"] = row["id"]
                    st.rerun()
            with col3:
                if st.button("🗑 Supprimer", key=f"del_{row['id']}"):
                    supabase.table("conditionnement").delete().eq("id", row["id"]).execute()
                    st.warning(f"🗑 Conditionnement {row['id']} supprimé.")
                    st.rerun()

        # Formulaire de modification
        if st.session_state.get("mod_conditionnement_id"):
            mod_id = st.session_state["mod_conditionnement_id"]
            record = df[df["id"] == mod_id].iloc[0]
            with st.form("form_mod_conditionnement"):
                new_remarque = st.text_input("📝 Nouvelle remarque", value=record["remarque"])
                new_emballage = st.selectbox("📦 Type d'emballage", ["Paquet", "Enveloppe"], index=["Paquet", "Enveloppe"].index(record["type_emballage"]))
                new_qte = st.number_input("🔢 Nombre de cartes", value=record["nombre_cartes"], min_value=1)
                submit_mod = st.form_submit_button("✅ Enregistrer les modifications")
                if submit_mod:
                    supabase.table("conditionnement").update({
                        "remarque": new_remarque,
                        "type_emballage": new_emballage,
                        "nombre_cartes": new_qte
                    }).eq("id", mod_id).execute()
                    st.success("✅ Conditionnement modifié avec succès.")
                    st.session_state["mod_conditionnement_id"] = None
                    st.rerun()


#Module gestion des agences
elif menu == "⚙️ Gestion des agences":
    st.markdown("## ⚙️ Gestion des agences de livraison")

    # 📋 Liste des agences existantes
    st.subheader("📋 Liste des agences existantes")
    try:
        response = supabase.table("agences_livraison").select("*").execute()
        df_agences = pd.DataFrame(response.data)
        st.dataframe(df_agences, use_container_width=True)
    except Exception as e:
        st.error(f"Erreur lors de la lecture des données : {e}")

    st.divider()

    # 🛠 Choix de l'action
    action = st.radio("Choisissez une action :", ["Ajouter", "Modifier", "Supprimer"])

    if action == "Ajouter":
        st.subheader("➕ Ajouter une nouvelle agence")
        nouveau_pays = st.text_input("Pays")
        nouvelle_agence = st.text_input("Nom de l'agence")
        
        if st.button("✅ Ajouter"):
            if nouveau_pays and nouvelle_agence:
                try:
            # 🔍 Vérification des doublons
                    doublon = supabase.table("agences_livraison").select("pays", "agence")\
                    .eq("pays", nouveau_pays)\
                    .eq("agence", nouvelle_agence).execute().data

                    if doublon:
                        st.warning(f"⚠️ L'agence '{nouvelle_agence}' pour le pays '{nouveau_pays}' existe déjà.")
                    else:
                # ✅ Ajout si pas de doublon
                        supabase.table("agences_livraison").insert({
                            "pays": nouveau_pays,
                            "agence": nouvelle_agence
                        }).execute()
                        st.success(f"✅ Agence ajoutée pour {nouveau_pays}")
                        st.rerun()
                except Exception as e:
                    st.warning(f"⚠️ Erreur : {e}")
            else:
                st.warning("Veuillez renseigner tous les champs.")

    elif action == "Modifier":
        st.subheader("✏️ Modifier une agence existante")
        response = supabase.table("agences_livraison").select("pays, agence").execute()
        agences = [(row["pays"], row["agence"]) for row in response.data]
        if agences:
            agence_selectionnee = st.selectbox("Sélectionnez une agence :", agences, format_func=lambda x: f"{x[0]} - {x[1]}")
            nouveau_nom = st.text_input("Nouveau nom de l'agence", value=agence_selectionnee[1])
            if st.button("✅ Modifier"):
                supabase.table("agences_livraison").update({"agence": nouveau_nom}).eq("pays", agence_selectionnee[0]).execute()
                st.success(f"✏️ Agence modifiée pour {agence_selectionnee[0]}")
                st.rerun()
        else:
            st.info("Aucune agence disponible pour modification.")

    elif action == "Supprimer":
        st.subheader("🗑️ Supprimer une agence existante")
        response = supabase.table("agences_livraison").select("pays, agence").execute()
        agences = [(row["pays"], row["agence"]) for row in response.data]
        if agences:
            agence_selectionnee = st.selectbox("Sélectionnez une agence à supprimer :", agences, format_func=lambda x: f"{x[0]} - {x[1]}")
            if st.button("🗑️ Supprimer"):
                supabase.table("agences_livraison").delete().eq("pays", agence_selectionnee[0]).execute()
                st.warning(f"🗑️ Agence supprimée pour {agence_selectionnee[0]}")
                st.rerun()
        else:
            st.info("Aucune agence disponible pour suppression.")

#Module expédition des lots
elif menu == "🚚 Expédition des lots":
    st.markdown("## 🚚 Préparation des expéditions")

    # 📅 Sélection de la date d'enregistrement
    selected_date = st.date_input("📅 Sélectionnez une date d'enregistrement :", value=date.today())

# 🌍 Choix du pays destinataire
    pays = st.selectbox("🌍 Pays destinataire :", [
        "Burkina Faso", "Mali", "Niger", "Côte d'Ivoire", "Sénégal",
        "Bénin", "Togo", "Guinée Conakry", "Guinée Bissau"
    ])

# 📦 Récupération des lots enregistrés à cette date et pour le pays sélectionné
    try:
        lots_response = supabase.table("lots").select("id, nom_lot, date_enregistrement, filiale")\
           .eq("date_enregistrement", str(selected_date)).eq("filiale", pays).execute()
        lots = [(lot["id"], lot["nom_lot"]) for lot in lots_response.data]
    except Exception as e:
        st.error(f"Erreur lors de la récupération des lots : {e}")
        lots = []

    lot_selectionne = st.selectbox("📦 Sélectionnez un lot à expédier :", lots, format_func=lambda x: x[1])
    lot_id = lot_selectionne[0] if lot_selectionne else None

    # 🚦 Statut d'expédition
    statut = st.radio("Statut d'expédition :", ["En attente", "En cours d'expédition", "Expédié"])

    # 📄 Numéro de bordereau
    bordereau = st.text_input("Numéro de bordereau")

    # 📌 Référence d'expédition
    try:
        ref_response = supabase.table("references_expedition").select("reference").eq("pays", pays).execute()
        reference = ref_response.data[0]["reference"] if ref_response.data else "Référence non disponible"
    except Exception:
        reference = "Référence non disponible"
    st.text_area("📌 Référence d'expédition", value=reference, disabled=True)

    # 🚚 Agence de livraison
    try:
        agence_response = supabase.table("agences_livraison").select("agence").eq("pays", pays).execute()
        agence = agence_response.data[0]["agence"] if agence_response.data else "Agence non définie"
    except Exception:
        agence = "Agence non définie"
    st.text_input("🚚 Agence de livraison", value=agence, disabled=True)

    # 👤 Sélection de l'agent livreur
    try:
        agents_response = supabase.table("livreurs").select("id, nom, prenom").eq("agence", agence).execute()
        agents = [(agent["id"], agent["nom"], agent["prenom"]) for agent in agents_response.data]
    except Exception:
        agents = []

    if agents:
        agent_selectionne = st.selectbox("👤 Sélectionnez un agent livreur :", agents, format_func=lambda x: f"{x[1]} {x[2]}")
        agent_id = agent_selectionne[0]
    else:
        st.warning("Aucun livreur disponible pour cette agence.")
        agent_id = None

    # ✅ Enregistrement de l'expédition
    if st.button("✅ Enregistrer l'expédition") and lot_id and agent_id:
        try:         
            # Récupérer le dernier ID existant
            last_id_data = supabase.table("expedition").select("id").order("id", desc=True).limit(1).execute().data
            next_id = (last_id_data[0]["id"] + 1) if last_id_data else 1           
            
            doublon = supabase.table("expedition").select("lot_id")\
                .eq("lot_id", lot_id).execute().data

            if doublon:
                st.warning("⚠️ Ce lot a déjà été enregistré pour une expédition.")
            else:
            # ✅ Enregistrement si pas de doublon
                supabase.table("expedition").insert({
                    "lot_id": lot_id,
                    "pays": pays,
                    "statut": statut,
                    "bordereau": bordereau,
                    "reference": reference,
                    "agence": agence,
                    "agent_id": agent_id,
                    "date_expedition": str(date.today())
                }).execute()
                st.success("✅ Expédition enregistrée avec succès.")
                st.rerun()
        except Exception as e:
            st.error(f"Erreur lors de l'enregistrement : {e}")

#Module annuaire de livraison
elif menu == "📇 Annuaire des livreurs":
    st.markdown("## 📇 Annuaire des livreurs")

    # 🔍 Récupération des livreurs
    try:
        livreurs_response = supabase.table("livreurs").select("id, agence, nom, prenom, contact").execute()
        livreurs = livreurs_response.data
        df_livreurs = pd.DataFrame(livreurs)
        st.dataframe(df_livreurs, use_container_width=True)
    except Exception as e:
        st.error(f"Erreur lors de la récupération des livreurs : {e}")
        livreurs = []

    # 🔍 Récupération des agences existantes
    try:
        agences_response = supabase.table("agences_livraison").select("agence").execute()
        agences_existantes = [row["agence"] for row in agences_response.data]
    except Exception as e:
        st.error(f"Erreur lors de la récupération des agences : {e}")
        agences_existantes = []

    # ➕ Ajout d'un livreur
    st.subheader("➕ Ajouter un livreur")
    with st.form("form_ajout_livreur"):
        col1, col2 = st.columns(2)
        with col1:
            agence = st.selectbox("Agence de livraison", agences_existantes)
            nom = st.text_input("Nom")
            prenom = st.text_input("Prénom")
        with col2:
            contact = st.text_input("Contact")
        submit_ajout = st.form_submit_button("✅ Ajouter")
        if submit_ajout:
            try:
               # 🔍 Vérification des doublons : même agence + même nom + même prénom
                doublon = supabase.table("livreurs").select("agence", "nom", "prenom")\
                    .eq("agence", agence)\
                    .eq("nom", nom)\
                    .eq("prenom", prenom).execute().data

                if doublon:
                    st.warning(f"⚠️ Le livreur {nom} {prenom} existe déjà pour l'agence {agence}.")
                else:
                # ✅ Ajout si pas de doublon
                    supabase.table("livreurs").insert({
                        "agence": agence,
                        "nom": nom,
                        "prenom": prenom,
                        "contact": contact
                    }).execute()
                    st.success(f"✅ Livreurs ajouté pour l'agence {agence}")
                    st.rerun()
            except Exception as e:
                st.error(f"Erreur lors de l'ajout : {e}")

    # ✏️ Modification / Suppression
    st.subheader("🛠️ Modifier ou Supprimer un livreur")
    livreur_dict = {f"{l['agence']} - {l['nom']} {l['prenom']} ({l['contact']})": l["id"] for l in livreurs}
    selected_livreur = st.selectbox("Sélectionner un livreur", list(livreur_dict.keys()))
    livreur_id = livreur_dict[selected_livreur]

    selected_data = next((l for l in livreurs if l["id"] == livreur_id), None)
    if selected_data:
        with st.form("form_modif_livreur"):
            col1, col2 = st.columns(2)
            with col1:
                new_agence = st.selectbox("Agence", agences_existantes, index=agences_existantes.index(selected_data["agence"]) if selected_data["agence"] in agences_existantes else 0)
                new_nom = st.text_input("Nom", value=selected_data["nom"])
            with col2:
                new_prenom = st.text_input("Prénom", value=selected_data["prenom"])
                new_contact = st.text_input("Contact", value=selected_data["contact"])
            action = st.radio("Action", ["Modifier", "Supprimer"])
            submitted = st.form_submit_button("✅ Valider")

            if submitted:
                if action == "Modifier":
                    try:
                        supabase.table("livreurs").update({
                            "agence": new_agence,
                            "nom": new_nom,
                            "prenom": new_prenom,
                            "contact": new_contact
                        }).eq("id", livreur_id).execute()
                        st.success("✏️ Livreurs modifié avec succès.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Erreur lors de la modification : {e}")
                elif action == "Supprimer":
                    try:
                        supabase.table("livreurs").delete().eq("id", livreur_id).execute()
                        st.warning("🗑️ Livreurs supprimé.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Erreur lors de la suppression : {e}")

#Module visualisation des expéditions

elif menu == "📦 Visualisation des expéditions":
    st.markdown("## 📦 Visualisation des expéditions")

    # 🔍 Récupération des expéditions
    try:
        df = pd.DataFrame(supabase.table("expedition").select("statut, agence").execute().data)
    except Exception as e:
        st.error(f"Erreur lors de la récupération des expéditions : {e}")
        df = pd.DataFrame()

    if df.empty:
        st.warning("Aucune expédition enregistrée.")
    else:
        # 📊 Indicateurs par statut
        en_attente = df[df["statut"] == "En attente"].shape[0]
        en_cours = df[df["statut"] == "En cours d'expédition"].shape[0]
        expediees = df[df["statut"] == "Expédié"].shape[0]

        col1, col2, col3 = st.columns(3)
        col1.metric("🕒 En attente", en_attente)
        col2.metric("🚚 En cours", en_cours)
        col3.metric("✅ Expédiées", expediees)

        st.divider()
        st.subheader("🏢 Répartition par agence de livraison")

        agence_counts = df["agence"].value_counts().reset_index()
        agence_counts.columns = ["Agence", "Nombre"]
        cols = st.columns(len(agence_counts))
        for i, row in agence_counts.iterrows():
            cols[i].metric(f"🏢 {row['Agence']}", row["Nombre"])

    st.divider()
    st.markdown("## 📋 Inventaire des expéditions enregistrées")

    try:
        expeditions = supabase.table("expedition").select("*").execute().data
        lots = supabase.table("lots").select("id, nom_lot").execute().data
        livreurs = supabase.table("livreurs").select("id, nom, prenom").execute().data

        lots_dict = {lot["id"]: lot["nom_lot"] for lot in lots}
        livreurs_dict = {livreur["id"]: f"{livreur['nom']} {livreur['prenom']}" for livreur in livreurs}

        for exp in expeditions:
            exp["nom_lot"] = lots_dict.get(exp["lot_id"], "Inconnu")
            exp["agent_livreur"] = livreurs_dict.get(exp["agent_id"], "Non attribué")

        df_expeditions = pd.DataFrame(expeditions)

    # 📊 Filtres latéraux
        st.sidebar.header("🔍 Filtres Inventaire des expéditions")

# Pays destinataire
        pays_selection = st.sidebar.multiselect(
            "Pays destinataire",
            df_expeditions["pays"].dropna().unique(),
            default=df_expeditions["pays"].dropna().unique()
        )

# Statut d'expédition
        statut_selection = st.sidebar.multiselect(
            "Statut",
            df_expeditions["statut"].dropna().unique(),
            default=df_expeditions["statut"].dropna().unique()
        )

# Agence de livraison
        agence_selection = st.sidebar.multiselect(
            "Agence de livraison",
            df_expeditions["agence"].dropna().unique(),
            default=df_expeditions["agence"].dropna().unique()
        )

# Nom du colis
        colis_selection = st.sidebar.multiselect(
            "Nom du colis",
            df_expeditions["nom_lot"].dropna().unique(),
            default=df_expeditions["nom_lot"].dropna().unique()
        )

# Agent livreur
        agent_selection = st.sidebar.multiselect(
            "Agent livreur",
            df_expeditions["agent_livreur"].dropna().unique(),
            default=df_expeditions["agent_livreur"].dropna().unique()
        )
        
# Numéro de bordereau
        bordereau_selection = st.sidebar.multiselect(
           "Numéro de bordereau",
           df_expeditions["bordereau"].dropna().unique(),
           default=df_expeditions["bordereau"].dropna().unique()
        )


# 📋 Application des filtres
        df_filtered = df_expeditions[
        (df_expeditions["pays"].isin(pays_selection)) &
        (df_expeditions["statut"].isin(statut_selection)) &
        (df_expeditions["agence"].isin(agence_selection)) &
        (df_expeditions["nom_lot"].isin(colis_selection)) &
        (df_expeditions["agent_livreur"].isin(agent_selection)) &
        (df_expeditions["bordereau"].isin(bordereau_selection))
        ]
    except Exception as e:
        st.error(f"Erreur lors de la récupération des données d'expédition : {e}")
        df_expeditions = pd.DataFrame()

    if df_expeditions.empty:
        st.warning("Aucune expédition enregistrée.")
    else:
        st.dataframe(df_filtered, use_container_width=True)

        st.subheader("🛠️ Gestion des expéditions")
        for index, row in df_filtered.iterrows():
            col1, col2, col3 = st.columns([4, 1, 1])
            with col1:
                st.write(
                    f"📦 **{row['nom_lot']}** | {row['pays']} | {row['statut']} | {row['bordereau']} | "
                    f"{row['agence']} | {row['agent_livreur']} | {row['date_expedition']}"
                )
            with col2:
                if st.button("✏️ Modifier", key=f"mod_{index}"):
                    st.session_state["mod_expedition_id"] = row["id"]
                    st.rerun()

            if st.session_state.get("mod_expedition_id") == row["id"]:
                with st.form(f"form_mod_expedition_{index}"):
                    new_statut = st.selectbox(
                        "Nouveau statut",
                        ["En attente", "En cours d'expédition", "Expédié"],
                        index=["En attente", "En cours d'expédition", "Expédié"].index(row["statut"])
                    )
                    submitted = st.form_submit_button("✅ Enregistrer les modifications")
                    if submitted:
                        try:
                            supabase.table("expedition").update({"statut": new_statut}).eq("id", row["id"]).execute()
                            st.success("✅ Statut modifié avec succès.")
                            st.session_state["mod_expedition_id"] = None
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erreur lors de la modification : {e}")

            with col3:
                if st.button("🗑️ Supprimer", key=f"del_{index}"):
                    try:
                        supabase.table("expedition").delete().eq("id", row["id"]).execute()
                        st.warning("🗑️ Expédition supprimée.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Erreur lors de la suppression : {e}")


#Gestion des comptes utilisateurs

elif menu == "🔐 Gestion des comptes utilisateurs":
    st.markdown("<h2 style='text-align:center;'>🔐 Gestion des comptes utilisateurs</h2>", unsafe_allow_html=True)
    st.markdown("<hr>", unsafe_allow_html=True)

    if st.session_state.get("role") != "admin":
        st.error("⛔ Accès réservé aux administrateurs.")
        st.stop()

    onglet = st.radio("📌 Choisissez une action :", [
        "➕ Ajouter un utilisateur",
        "✏️ Modifier un utilisateur",
        "🔄 Activer/Désactiver un compte",
        "🗑️ Supprimer un utilisateur"
    ])

    # ➕ Ajouter un utilisateur
    if onglet == "➕ Ajouter un utilisateur":
        st.markdown("### ➕ Ajouter un nouvel utilisateur")
        with st.form("form_ajout_utilisateur"):
            col1, col2 = st.columns(2)
            with col1:
                new_id = st.text_input("👤 Identifiant")
                new_role = st.selectbox("🎯 Rôle", ["admin", "operateur"])
            with col2:
                new_pwd = st.text_input("🔑 Mot de passe", type="password")
            submit = st.form_submit_button("✅ Créer le compte")
            if submit and new_id and new_pwd:
                existing = supabase.table("utilisateurs").select("identifiant").eq("identifiant", new_id).execute().data
                if existing:
                    st.error("❌ Cet identifiant existe déjà.")
                else:                    
                    last_id_data = supabase.table("utilisateurs").select("id").order("id", desc=True).limit(1).execute().data
                    next_id = (last_id_data[0]["id"] + 1) if last_id_data else 1
                    supabase.table("utilisateurs").insert({
                        "identifiant": new_id,
                        "mot_de_passe": hashlib.sha256(new_pwd.encode()).hexdigest(),
                        "role": new_role,
                        "doit_changer_mdp": 1,
                        "actif": 1
                    }).execute()
                    st.success("✅ Utilisateur ajouté avec succès.")
                    st.rerun()

    # ✏️ Modifier un utilisateur
    
    elif onglet == "✏️ Modifier un utilisateur":
        st.markdown("### ✏️ Modifier l'identifiant ou le rôle d'un utilisateur")
        users = supabase.table("utilisateurs").select("identifiant", "role").execute().data
        user_list = [u["identifiant"] for u in users]
        selected_user = st.selectbox("👤 Choisir un utilisateur", user_list)

        with st.form("form_modif_utilisateur_simple"):
            col1, col2 = st.columns(2)
            with col1:
                new_identifiant = st.text_input("🆕 Nouvel identifiant", value=selected_user)
            with col2:
                new_role = st.selectbox("🎯 Nouveau rôle", ["admin", "operateur"])
            submit = st.form_submit_button("✅ Mettre à jour")

            if submit and new_identifiant:
                if new_identifiant != selected_user:
                    exists = supabase.table("utilisateurs").select("identifiant").eq("identifiant", new_identifiant).execute().data
                    if exists:
                        st.error("❌ Ce nouvel identifiant est déjà utilisé.")
                        st.stop()
                supabase.table("utilisateurs").update({
                    "identifiant": new_identifiant,
                    "role": new_role
                }).eq("identifiant", selected_user).execute()
                st.success("✅ Utilisateur mis à jour avec succès.")
                st.rerun()


    # 🔄 Activer/Désactiver un compte
    elif onglet == "🔄 Activer/Désactiver un compte":
        st.markdown("### 🔄 Activer ou désactiver un compte")
        users = supabase.table("utilisateurs").select("identifiant, actif").execute().data
        for user in users:
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"👤 {user['identifiant']} — {'✅ Actif' if user['actif'] else '⛔ Inactif'}")
            with col2:
                if st.button("🔁 Basculer", key=user["identifiant"]):
                    nouveau_statut = 0 if user["actif"] else 1
                    supabase.table("utilisateurs").update({"actif": nouveau_statut}).eq("identifiant", user["identifiant"]).execute()
                    st.rerun()

    # 🗑️ Supprimer un utilisateur
    elif onglet == "🗑️ Supprimer un utilisateur":
        st.markdown("### 🗑️ Supprimer un utilisateur")
        users = supabase.table("utilisateurs").select("identifiant").neq("identifiant", "admin").execute().data
        user_list = [u["identifiant"] for u in users]
        selected_user = st.selectbox("👤 Utilisateur à supprimer", user_list)
        if st.button("🗑️ Supprimer"):
            supabase.table("utilisateurs").delete().eq("identifiant", selected_user).execute()
            st.success("✅ Utilisateur supprimé.")
            st.rerun()


# Message de bienvenue et déconnexion
st.sidebar.success(
    f"👤 {st.session_state.get('display_name', 'Utilisateur')} est connecté"
)
# --- Ici commencent tes modules une fois l'utilisateur authentifié ---
#st.sidebar.success(f"👤 {st.session_state.get('display_name', 'Utilisateur')} ({st.session_state.get('role','?')})")
if st.sidebar.button("🔓 Se déconnecter"):
    logout()
    st.rerun()
