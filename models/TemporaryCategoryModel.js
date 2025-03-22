class TemporaryCategory {
    constructor({
      id,
      titre,
      description,
      niveau, // "facile", "moyen", "difficile"
      nombre_questions,
      auteur, // Référence à un utilisateur (ID ou objet User)
      approuve,
      date_soumission,
    }) {
      this.id = id;
      this.titre = titre;
      this.description = description;
      this.niveau = niveau || 'facile';
      this.nombre_questions = nombre_questions || 0;
      this.auteur = auteur; // Référence à un utilisateur (par exemple, un ID)
      this.approuve = approuve || false;
      this.date_soumission = date_soumission || new Date();
    }
  
    toObject() {
      return {
        titre: this.titre,
        description: this.description,
        niveau: this.niveau,
        nombre_questions: this.nombre_questions,
        auteur: this.auteur,
        approuve: this.approuve,
        date_soumission: this.date_soumission,
      };
    }
  }
  
  module.exports = TemporaryCategory;