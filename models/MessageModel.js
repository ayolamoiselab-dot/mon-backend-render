// models/MessageModel.js
class Message {
    constructor({
      id,
      discussionId,  // Référence vers la salle de discussion
      userId,         // ID de l’utilisateur qui envoie le message
      content,        // texte du message
      createdAt,
    }) {
      this.id = id;
      this.discussionId = discussionId;
      this.userId = userId;
      this.content = content || "";
      this.createdAt = createdAt || new Date();
    }
  }
  
  module.exports = Message;
  