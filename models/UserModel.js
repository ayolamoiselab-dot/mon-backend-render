const bcrypt = require('bcrypt');

class User {
  constructor({
    id,
    firstName,
    lastName,
    email,
    password,
    role,                  // "Etudiant", "Enseignant", "Autodidacte", ...
    verificationDocuments, // Array de string (URLs) pour prouver la profession
    idCardFront,           // URL ou chemin du recto de la pièce d'identité
    idCardBack,            // URL ou chemin du verso
    isTeacherVerified,     // booléen pour valider un enseignant
    createdAt,
    updatedAt,
    preferredDomains,      // Nouveau champ pour les domaines préférés
    learningResources,     // Ressources externes sauvegardées
    bio,                   // Nouveau champ
    competences,           // Nouveau champ
    isProfileComplete      // Nouveau champ
  }) {
    this.id = id;
    this.firstName = firstName;
    this.lastName = lastName;
    this.email = email;
    this.password = password;
    this.role = role;
    this.verificationDocuments = verificationDocuments || [];
    this.idCardFront = idCardFront || null;
    this.idCardBack = idCardBack || null;
    this.isTeacherVerified = isTeacherVerified || false;
    this.createdAt = createdAt || new Date();
    this.updatedAt = updatedAt || new Date();
    this.preferredDomains = preferredDomains || [];
    this.learningResources = learningResources || [];
    this.bio = bio || '';
    this.competences = competences || [];
    this.isProfileComplete = isProfileComplete || false;
  }

  // Méthode pour hasher le mot de passe
  static async hashPassword(password) {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
  }

  // Méthode pour comparer un mot de passe en clair et un hash
  static async comparePassword(password, hash) {
    return await bcrypt.compare(password, hash);
  }

  // Méthode pour convertir l'instance en un objet brut (plain object)
  toObject() {
    return {
      firstName: this.firstName,
      lastName: this.lastName,
      email: this.email,
      password: this.password,
      role: this.role,
      verificationDocuments: this.verificationDocuments,
      idCardFront: this.idCardFront,
      idCardBack: this.idCardBack,
      isTeacherVerified: this.isTeacherVerified,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      preferredDomains: this.preferredDomains,
      learningResources: this.learningResources,
      bio: this.bio,                   // Nouveau champ
      competences: this.competences,   // Nouveau champ
      isProfileComplete: this.isProfileComplete, // Nouveau champ
    };
  }
}

module.exports = User;
