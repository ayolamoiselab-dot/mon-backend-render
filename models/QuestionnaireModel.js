class Questionnaire {
  constructor({
    id,
    titre,
    description,
    categorie, // Référence à une CategorieQuiz (ID Firestore)
    niveau, // "facile", "intermediaire", "avance"
    niveau_suivant, // Référence à un autre Questionnaire (ID Firestore ou null)
    date_creation,
    update,
    auteur, // Référence à un utilisateur (ID Firestore)
  }) {
    this.id = id;
    this.titre = titre;
    this.description = description || '';
    this.categorie = categorie; // ID de la catégorie dans Firestore
    this.niveau = niveau || 'facile';
    this.niveau_suivant = niveau_suivant || null; // ID du questionnaire suivant ou null
    this.date_creation = date_creation || new Date();
    this.update = update || new Date();
    this.auteur = auteur || 'admin'; // ID de l’utilisateur (par exemple, email ou UID)
  }

  toObject() {
    return {
      titre: this.titre,
      description: this.description,
      categorie: this.categorie,
      niveau: this.niveau,
      niveau_suivant: this.niveau_suivant,
      date_creation: this.date_creation,
      update: this.update,
      auteur: this.auteur,
    };
  }
}

module.exports = Questionnaire;