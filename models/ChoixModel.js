class Choix {
  constructor({
    id,
    texte,
    est_correct,
    question, // Référence à une Question (ID Firestore)
  }) {
    this.id = id;
    this.texte = texte;
    this.est_correct = est_correct || false;
    this.question = question; // ID de la question dans Firestore
  }

  toObject() {
    return {
      texte: this.texte,
      est_correct: this.est_correct,
      question: this.question,
    };
  }
}

module.exports = Choix;