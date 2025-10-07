import math
import streamlit as st
from supabase import create_client
import pandas as pd
from datetime import date
import hashlib

import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from sklearn.linear_model import LinearRegression

st.set_page_config(
    page_title="DSTM",
    page_icon="Designer.png",  # ton icône
    layout="wide"
)

# Connexion à Supabase
url = st.secrets["supabase_url"]
key = st.secrets["supabase_key"]
supabase = create_client(url, key)

# Fonction de hachage du mot de passe
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Fonction de connexion utilisateur
def login_form():
    st.markdown("<h2 style='text-align: center;'>🔐 Connexion à l'application ERP</h2>", unsafe_allow_html=True)
    st.markdown("<div style='text-align: center;'>Veuillez entrer vos identifiants pour accéder à l'application.</div>", unsafe_allow_html=True)
    st.divider()
    with st.form("login_form"):
        st.image("imageExcelis.png", width=200)
        st.markdown("<h6 style='text-align: center; color: grey;'><em>Département Cartes et Partenariat DCP</em></h6>", unsafe_allow_html=True)
        st.markdown("<div style='display: flex; justify-content: center;'>", unsafe_allow_html=True)
        col1, col2 = st.columns([1, 2])
        with col2:
            identifiant = st.text_input("Identifiant")
            mot_de_passe = st.text_input("Mot de passe", type="password")
            submit = st.form_submit_button("✅ Se connecter")
        st.markdown("</div>", unsafe_allow_html=True)

    if submit:
        result = supabase.table("utilisateurs").select("mot_de_passe, role, doit_changer_mdp").eq("identifiant", identifiant).execute().data
        if result and result[0]["mot_de_passe"] == hash_password(mot_de_passe):
            st.session_state["utilisateur"] = identifiant
            st.session_state["role"] = result[0]["role"]
            st.session_state["doit_changer_mdp"] = result[0]["doit_changer_mdp"]
            st.success("✅ Connexion réussie")
            st.rerun()
        else:
            st.error("❌ Identifiants incorrects")

# Blocage de l'accès si non connecté
if "utilisateur" not in st.session_state:
    login_form()
    st.stop()

# Blocage si mot de passe doit être changé
if "doit_changer_mdp" in st.session_state and st.session_state["doit_changer_mdp"]:
    def changer_mot_de_passe():
        st.warning("🔄 Vous devez changer votre mot de passe.")
        nouveau_mdp = st.text_input("Nouveau mot de passe", type="password")
        confirmer_mdp = st.text_input("Confirmer le mot de passe", type="password")
        if st.button("✅ Mettre à jour"):
            if nouveau_mdp == confirmer_mdp and nouveau_mdp != "":
                supabase.table("utilisateurs").update({
                    "mot_de_passe": hash_password(nouveau_mdp),
                    "doit_changer_mdp": False
                }).eq("identifiant", st.session_state["utilisateur"]).execute()
                st.success("🔐 Mot de passe mis à jour avec succès.")
                st.session_state["doit_changer_mdp"] = False
                st.rerun()
            else:
                st.error("❌ Les mots de passe ne correspondent pas ou sont vides.")
    changer_mot_de_passe()
    st.stop()

# Exemple d'enregistrement d'un lot
def enregistrer_lot():
    st.markdown("## ➕ Enregistrement d'un nouveau lot")
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
                    "cartes_a_tester": cartes_a_tester
                }).execute()
                st.success("✅ Lot enregistré avec succès.")
                st.rerun()


st.markdown("<h1 style='text-align: center;'>Gestion des tâches manuelles section DCP</h1>", unsafe_allow_html=True)
st.divider()
# Menu latéral avec icône burger
with st.sidebar:
    st.image("imageExcelis.png", width=200)
    st.markdown("<h6 style='text-align: center; color: grey;'><em>Département Cartes et Partenariat DCP</em></h6>", unsafe_allow_html=True)
    
    menu = st.selectbox("Naviguer vers :", [
        "➕ Enregistrement des lots",
        "📋 Visualisation des lots",
        "✏️ Modification / Suppression",
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

if menu == "➕ Enregistrement des lots":
    enregistrer_lot()


elif menu == "📋 Visualisation des lots":
    from supabase import create_client
    import pandas as pd

    # Connexion à Supabase
    url = st.secrets["supabase_url"]
    key = st.secrets["supabase_key"]
    supabase = create_client(url, key)

    st.markdown("## 📋 Liste des lots enregistrés")

    # Récupération des données depuis Supabase
    response = supabase.table("lots").select("*").execute()
    lots_data = response.data

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

        st.dataframe(df_filtered, use_container_width=True)
    else:
        st.warning("Aucun lot enregistré dans la base de données Supabase.")


elif menu == "✏️ Modification / Suppression":
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

    st.markdown("## 🧪 Enregistrement d'un contrôle qualité")

    # Récupération des lots
    response = supabase.table("lots").select("id", "nom_lot").execute()
    lots = response.data
    if not lots:
        st.warning("Aucun lot disponible.")
        st.stop()

    lot_dict = {f"{lot['id']} - {lot['nom_lot']}": lot["id"] for lot in lots}
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

    # Résumé
    if types_selectionnes:
        st.subheader("📋 Résumé des tests")
        for type_carte in types_selectionnes:
            st.write(f"{type_carte} : {quantites[type_carte]} cartes → {quantites_a_tester[type_carte]} à tester")
        st.write(f"🔢 Total des cartes à tester : {total_a_tester}")


elif menu == "🗂 Inventaire des tests":
    st.markdown("## 🗂 Inventaire des tests de contrôle qualité")

    # Récupération des données depuis Supabase
    response = supabase.table("controle_qualite").select(
        "id, date_controle, type_carte, quantite, quantite_a_tester, remarque, resultat, lot_id"
    ).execute()

    controle_data = response.data

    # Récupération des noms de lots et filiales
    lots_response = supabase.table("lots").select("id, nom_lot, filiale").execute()
    lots_data = {lot["id"]: (lot["nom_lot"], lot["filiale"]) for lot in lots_response.data}

    # Fusion des données
    for row in controle_data:
        lot_info = lots_data.get(row["lot_id"], ("Inconnu", ""))
        row["nom_lot"] = lot_info[0]
        row["filiale"] = lot_info[1]

    df = pd.DataFrame(controle_data)

    if df.empty:
        st.warning("Aucun test de contrôle qualité enregistré.")
    else:
        df["date_controle"] = pd.to_datetime(df["date_controle"])
        df["Année"] = df["date_controle"].dt.year
        df["Mois"] = df["date_controle"].dt.month_name()
        df["Trimestre"] = df["date_controle"].dt.quarter
        df["Semaine"] = df["date_controle"].dt.isocalendar().week
        df["Jour"] = df["date_controle"].dt.day
        df["Jour_Semaine"] = df["date_controle"].dt.day_name()

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
        col1.metric("Total cartes testées", total_testees)
        col2.metric("Tests réussis", nb_reussites)
        col3.metric("Tests échoués", nb_echecs)

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



# Bloc Graphiques et Analyses
elif menu == "📊 Graphiques et Analyses":
    st.markdown("## 📊 Tableau de bord des indicateurs")

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

        # Conversion des dates
        lots_df["date_enregistrement"] = pd.to_datetime(lots_df["date_enregistrement"], errors="coerce")
        controle_df["date_controle"] = pd.to_datetime(controle_df["date_controle"], errors="coerce")

        # KPIs sur les lots
        st.header("Lots Enregistrés")
        total_lots = len(lots_df)
        total_cartes = lots_df["quantite"].sum()
        moyenne_cartes = lots_df["quantite"].mean()
        lots_avec_pin = lots_df[lots_df["impression_pin"] == "Oui"].shape[0]
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Nombre total de lots", total_lots)
        col2.metric("Total cartes produites", total_cartes)
        col3.metric("Moyenne cartes/lot", f"{moyenne_cartes:.2f}")
        col4.metric("Lots avec impression PIN", lots_avec_pin)

        # Graphique cônes 3D par type de lot
        types_lot = lots_df["type_lot"].unique().tolist()
        quantites = lots_df.groupby("type_lot")["quantite"].sum().tolist()
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
            title="📊 Répartition des lots par type de lot (Cônes 3D)",
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

        # Graphique Mesh3D production mensuelle
        import plotly.graph_objects as go
        import numpy as np
    
# Conversion des dates et extraction du mois
        lots_df["date_enregistrement"] = pd.to_datetime(lots_df["date_enregistrement"], errors="coerce")
        lots_df["Mois"] = lots_df["date_enregistrement"].dt.month_name()
        lots_df["Mois"] = lots_df["Mois"].map({'January': 'Janvier', 'February': 'Février', 'March': 'Mars', 'April': 'Avril', 'May': 'Mai', 'June': 'Juin', 'July': 'Juillet', 'August': 'Août', 'September': 'Septembre', 'October': 'Octobre', 'November': 'Novembre', 'December': 'Décembre'})

# Agrégation mensuelle
        production_mensuelle = lots_df.groupby("Mois")["quantite"].sum().reset_index()

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
            title="📦 Production mensuelle des cartes (Mesh3D)",
            scene=dict(
                xaxis=dict(title="Mois", tickvals=x, ticktext=production_mensuelle["Mois"]),
                yaxis=dict(title=""),
                zaxis=dict(title="Quantité produite")
            ),
            margin=dict(l=0, r=0, b=0, t=40)
        )
        st.plotly_chart(fig, use_container_width=True)

        # Graphique cylindres 3D par trimestre
        lots_df["Année"] = lots_df["date_enregistrement"].dt.year
        lots_df["Trimestre"] = lots_df["date_enregistrement"].dt.quarter
        agg = lots_df.groupby(["Année", "Trimestre"])["quantite"].sum().reset_index()
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
            title="📦 Production trimestrielle en cylindres 3D",
            scene=dict(
                xaxis=dict(title="Trimestre", tickvals=list(range(len(agg))), ticktext=agg["Label"].tolist()),
                yaxis=dict(title=""),
                zaxis=dict(title="Cartes produites")
            ),
            margin=dict(l=0, r=0, b=0, t=40)
        )
        st.plotly_chart(fig, use_container_width=True)

        # KPIs sur le contrôle qualité
        st.header("Contrôle qualité")
        total_tests = controle_df["quantite_a_tester"].sum()
        nb_reussites = controle_df[controle_df["resultat"] == "Réussite"].shape[0]
        nb_echecs = controle_df[controle_df["resultat"] == "Échec"].shape[0]
        taux_reussite = (nb_reussites / (nb_reussites + nb_echecs)) * 100 if (nb_reussites + nb_echecs) > 0 else 0
        taux_echec = 100 - taux_reussite
        anomalies = controle_df[controle_df["remarque"].notna() & (controle_df["remarque"] != "")].shape[0]
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total cartes testées", total_tests)
        col2.metric("Taux de réussite", f"{taux_reussite:.2f}%")
        col3.metric("Taux d'échec", f"{taux_echec:.2f}%")
        col4.metric("Nombre d'anomalies signalées", anomalies)

        # Graphique barres par filiale
        df_grouped = controle_df.groupby("filiale")["quantite_a_tester"].sum().reset_index()
        fig = px.bar(df_grouped, x="filiale", y="quantite_a_tester", text="quantite_a_tester",
                     title="📊 Total des tests par filiale", labels={"filiale": "Filiale", "quantite_a_tester": "Tests"}, height=500)
        fig.update_traces(textposition="outside")
        st.plotly_chart(fig, use_container_width=True)

        # Conversion des dates
        controle_df["date_controle"] = pd.to_datetime(controle_df["date_controle"], errors="coerce")
        controle_df["Mois"] = controle_df["date_controle"].dt.to_period("M").astype(str)

        # Agrégation des données
        grouped = controle_df.groupby(["filiale", "type_carte"])["quantite_a_tester"].sum().reset_index()

        # Graphique interactif
        fig = px.bar(
            grouped,
            x="filiale",
            y="quantite_a_tester",
            color="type_carte",
            title="📊 Tests mensuels par carte et par filiale",
            labels={"quantite_a_tester": "Cartes testées", "type_carte": "Type de carte"},
            height=500
        )

        st.plotly_chart(fig, use_container_width=True)

        # Graphique barres par type de carte
        fig = px.bar(controle_df["type_carte"].value_counts().reset_index(), x="type_carte", y="count",
                     labels={"count": "Type de carte", "type_carte": "Nombre de tests"},
                     title="📊 Tests par type de carte")
        st.plotly_chart(fig, use_container_width=True)

        # Graphique pyramides 3D par mois
        controle_df["Mois"] = controle_df["date_controle"].dt.to_period("M").astype(str)
        tests_mensuels = controle_df.groupby("Mois")["quantite_a_tester"].sum().reset_index()
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
            title="📊 Nombre total de tests par mois (Pyramides 3D)",
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

   
        # Graphique prévision linéaire
        monthly_tests = controle_df.groupby("Mois")["quantite_a_tester"].sum().reset_index()
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
                      title="📈 Prévision des tests mensuels", labels={"quantite_a_tester": "Nombre de tests", "Mois": "Mois"})
        fig.update_layout(xaxis_title="Mois", yaxis_title="Nombre de tests")
        st.plotly_chart(fig, use_container_width=True)

        # Graphique courbe 3D par jour de la semaine
        controle_df["date_controle"] = pd.to_datetime(controle_df["date_controle"], errors="coerce")
        controle_df["Jour_Semaine"] = controle_df["date_controle"].dt.day_name()
        controle_df["Jour_Semaine"] = controle_df["Jour_Semaine"].map({'Monday': 'Lundi', 'Tuesday': 'Mardi', 'Wednesday': 'Mercredi', 'Thursday': 'Jeudi', 'Friday': 'Vendredi', 'Saturday': 'Samedi', 'Sunday': 'Dimanche'})
        tests_par_jour = controle_df.groupby("Jour_Semaine")["quantite_a_tester"].sum().reset_index()
    
        import plotly.graph_objects as go

# Ordre des jours
        jours_ordonne = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"]
        tests_par_jour["Jour_Semaine"] = pd.Categorical(tests_par_jour["Jour_Semaine"], categories=jours_ordonne, ordered=True)
        tests_par_jour = tests_par_jour.sort_values("Jour_Semaine")

        x = list(range(len(tests_par_jour)))
        y = [0] * len(tests_par_jour)
        z = tests_par_jour["quantite_a_tester"].tolist()
        labels = tests_par_jour["Jour_Semaine"].tolist()

        fig = go.Figure(data=[
            go.Scatter3d(
               x=x,
               y=y,
               z=z,
               mode='lines+markers+text',
               text=[f"{jour}<br>{val} tests" for jour, val in zip(labels, z)],
               line=dict(color='royalblue', width=4),
               marker=dict(size=6)
            )
        ])
        fig.update_layout(
            title="📈 Total des tests journaliers par jour de la semaine (Courbe 3D)",
            scene=dict(
                xaxis=dict(title="Jour", tickvals=x, ticktext=labels),
                yaxis=dict(title=""),
                zaxis=dict(title="Nombre de tests")
            ),
            margin=dict(l=0, r=0, b=0, t=40),
            scene_camera=dict(eye=dict(x=1.5, y=1.5, z=1.5))
        )
        st.plotly_chart(fig, use_container_width=True)

        # KPIs temporels
        st.header("📅 Évolution temporelle")
        
        lots_df["mois"] = lots_df["date_enregistrement"].dt.to_period("M").astype(str)
        evolution_lots = lots_df.groupby("mois")["quantite"].sum().reset_index()
        fig = px.line(evolution_lots, x="mois", y="quantite", markers=True,
                     title="📈 Évolution mensuelle des lots enregistrés",
                     labels={"mois": "Mois", "quantite": "Quantité totale"})
        st.plotly_chart(fig, use_container_width=True)
       
        controle_df["semaine"] = controle_df["date_controle"].dt.to_period("W").astype(str)
        evolution_tests = controle_df.groupby("semaine")["quantite_a_tester"].sum().reset_index()
        fig = px.bar(evolution_tests, x="semaine", y="quantite_a_tester",
                     title="📊 Évolution hebdomadaire des tests qualité",
                     labels={"semaine": "Semaine", "quantite_a_tester": "Nombre total de tests"},
                     height=600,
                     text="quantite_a_tester")
        fig.update_traces(marker_color="mediumseagreen", textposition="outside")
        fig.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(fig, use_container_width=True)


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
            st.write("📤 Emballage : Enveloppes grand format")

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
                remarque = st.text_input(
                        f"📝 Remarque pour le paquet {i} ({type_emballage})",
                        value="RAS",
                        key=f"remarque_{i}_{type_emballage}"
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

        # Enregistrement dans Supabase
        if st.button("✅ Enregistrer le conditionnement"):
            for _, row in df_conditionnement.iterrows():
                supabase.table("conditionnement").insert({
                    "lot_id": None,
                    "type_lot": row["Type de lot"],
                    "filiale": row["Filiale"],
                    "type_emballage": row["Conditionnement"],
                    "nombre_cartes": row["Quantité"],
                    "date_conditionnement": str(selected_date),
                    "operateur": st.session_state["utilisateur"],
                    "remarque": row["Remarque"],
                    "packs": row["Packs VIP"],
                    "nom_lot": row["Nom du lot"]
                }).execute()
            st.success("✅ Conditionnement enregistré avec succès.")


#Inventaire de conditionnements
elif menu == "🗂 Inventaire des conditionnements":
    st.markdown("## 🗂 Inventaire des conditionnements")

    response = supabase.table("conditionnement").select("*").execute()
    data = response.data

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
                    supabase.table("agences_livraison").insert({"pays": nouveau_pays, "agence": nouvelle_agence}).execute()
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
            last_id_data = supabase.table("expedition").select("id").order("id", desc=True).limit(1).execute().data
            next_id = (last_id_data[0]["id"] + 1) if last_id_data else 1
            supabase.table("expedition").insert({
                "id": next_id,
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
    st.markdown("## 📇 Annuaire des livreurs par agence")

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
    st.markdown("## 📦 Indicateurs des expéditions")

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
st.sidebar.success(f"{st.session_state['utilisateur']} est connecté")
if st.sidebar.button("🔓 Se déconnecter"):
    for key in ["utilisateur", "role", "doit_changer_mdp"]:
        st.session_state.pop(key, None)
    st.rerun()
