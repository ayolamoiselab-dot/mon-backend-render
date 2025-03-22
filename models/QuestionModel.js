class Question {
  constructor({
    id,
    texte,
    questionnaire, // Référence à un Questionnaire (ID Firestore)
  }) {
    this.id = id;
    this.texte = texte;
    this.questionnaire = questionnaire; // ID du questionnaire dans Firestore
  }

  toObject() {
    return {
      texte: this.texte,
      questionnaire: this.questionnaire,
    };
  }
}

module.exports = Question;