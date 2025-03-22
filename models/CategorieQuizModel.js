class CategorieQuiz {
    constructor({
      id,
      titre,
      description,
      auteur,
      date_creation,
      icon,
    }) {
      this.id = id;
      this.titre = titre;
      this.description = description || '';
      this.auteur = auteur; // Référence à un utilisateur (par exemple, email ou UID)
      this.date_creation = date_creation || new Date();
      this.icon = icon || '';
    }
  
    toObject() {
      return {
        titre: this.titre,
        description: this.description,
        auteur: this.auteur,
        date_creation: this.date_creation,
        icon: this.icon,
      };
    }
  }
  
  module.exports = CategorieQuiz;