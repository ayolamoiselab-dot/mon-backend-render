// models/ExerciseModel.js
class Exercise {
    constructor({
      id,
      courseId,    // Référence vers le document Course
      title,
      content,     // Énoncé, description ou lien d’énoncé
      createdAt,
      updatedAt,
    }) {
      this.id = id;
      this.courseId = courseId;
      this.title = title;
      this.content = content || "";
      this.createdAt = createdAt || new Date();
      this.updatedAt = updatedAt || new Date();
    }
  }
  
  module.exports = Exercise;
  