// models/DocumentModel.js
class DocumentModel {
    constructor({
      id,
      title,
      description,
      fileUrl,     // Lien vers le fichier (dans le storage)
      uploadedBy,  // ID de l'utilisateur qui l'a uploadé
      isPaid,
      price,
      createdAt,
      updatedAt,
    }) {
      this.id = id;
      this.title = title;
      this.description = description || "";
      this.fileUrl = fileUrl || "";
      this.uploadedBy = uploadedBy;  // userId
      this.isPaid = isPaid || false;
      this.price = price || 0;
      this.createdAt = createdAt || new Date();
      this.updatedAt = updatedAt || new Date();
    }
  }
  
  module.exports = DocumentModel;
  