class ResultatQuiz {
    constructor({
      id,
      user, // Référence à un utilisateur (ID ou objet User)
      categorie, // Référence à une CategorieQuiz (ID ou objet)
      niveau, // "facile", "intermediaire", "avance"
      score,
      score_cat,
      termine,
      date_passage,
    }) {
      this.id = id;
      this.user = user; // Référence à un utilisateur (par exemple, un ID)
      this.categorie = categorie; // Référence à une catégorie (par exemple, un ID)
      this.niveau = niveau || 'facile';
      this.score = score || 0;
      this.score_cat = score_cat || 0;
      this.termine = termine || false;
      this.date_passage = date_passage || new Date();
    }
  
    toObject() {
      return {
        user: this.user,
        categorie: this.categorie,
        niveau: this.niveau,
        score: this.score,
        score_cat: this.score_cat,
        termine: this.termine,
        date_passage: this.date_passage,
      };
    }
  }
  
  module.exports = ResultatQuiz;