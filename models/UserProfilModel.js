class UserProfil {
    constructor({
      id,
      user, // Référence à un utilisateur (ID ou objet User)
      date_joined,
    }) {
      this.id = id;
      this.user = user; // Référence à un utilisateur (par exemple, un ID)
      this.date_joined = date_joined || new Date();
    }
  
    toObject() {
      return {
        user: this.user,
        date_joined: this.date_joined,
      };
    }
  }
  
  module.exports = UserProfil;