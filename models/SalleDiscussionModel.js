// models/SalleDiscussionModel.js
class SalleDiscussion {
    constructor({
      id,
      subject,       // sujet ou thème de la discussion
      createdBy,     // userId de la personne qui ouvre la salle
      isOpen,        // booléen pour savoir si la salle est toujours active
      createdAt,
      updatedAt,
    }) {
      this.id = id;
      this.subject = subject || "";
      this.createdBy = createdBy;
      this.isOpen = isOpen !== undefined ? isOpen : true;
      this.createdAt = createdAt || new Date();
      this.updatedAt = updatedAt || new Date();
    }
  }
  
  module.exports = SalleDiscussion;
  