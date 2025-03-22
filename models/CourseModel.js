// models/CourseModel.js
class Course {
    constructor({
      id,
      title,
      description,
      teacherId,    // Référence (string) vers le document User de l'enseignant
      isPaid,       // true/false : si le cours est payant
      price,        // prix du cours si isPaid = true
      createdAt,
      updatedAt,
    }) {
      this.id = id;
      this.title = title;
      this.description = description;
      this.teacherId = teacherId;
      this.isPaid = isPaid || false;
      this.price = price || 0;
      this.createdAt = createdAt || new Date();
      this.updatedAt = updatedAt || new Date();
    }
  }
  
  module.exports = Course;
  