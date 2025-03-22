// models/QuizModel.js
class Quiz {
    constructor({
      id,
      title,
      theme,
      level,
      teacherId,   // Référence (string) vers le User (enseignant)
      questions,   // tableau de questions ou sous-collection
      createdAt,
      updatedAt,
    }) {
      this.id = id;
      this.title = title;
      this.theme = theme || "";
      this.level = level || 1;   // ex: 1 = facile, 2 = moyen, 3 = difficile
      this.teacherId = teacherId;
      this.questions = questions || [];
      this.createdAt = createdAt || new Date();
      this.updatedAt = updatedAt || new Date();
    }
  }
  
  module.exports = Quiz;
  