const cloudinary = require('cloudinary').v2;
const express = require('express');
const router = express.Router();
const axios = require('axios');
const WebSocket = require('ws');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');
const User = require('./models/UserModel');
const CategorieQuiz = require('./models/CategorieQuizModel');
const ResultatQuiz = require('./models/ResultatQuizModel');
const serviceAccount = {
  type: process.env.FIREBASE_TYPE || "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID || "miawodo-c5be2",
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID || "cd1a59cdd4d9113ab5f4351f9992318ed342712e",
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'), // Évaluation correcte
  client_email: process.env.FIREBASE_CLIENT_EMAIL || "firebase-adminsdk-fbsvc@miawodo-c5be2.iam.gserviceaccount.com",
  client_id: process.env.FIREBASE_CLIENT_ID || "117892011576494679572",
  auth_uri: process.env.FIREBASE_AUTH_URI || "https://accounts.google.com/o/oauth2/auth",
  token_uri: process.env.FIREBASE_TOKEN_URI || "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL || "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL || "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40miawodo-c5be2.iam.gserviceaccount.com",
  universe_domain: "googleapis.com"
};

const cors = require('cors');
const multer = require('multer');
//const videoRoutes = require('./routes/videoRoutes'); // Si tu as un fichier séparé pour les routes


const path = require('path');
require('dotenv').config();

// Configuration de Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configuration de multer pour l'upload des fichiers
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

// Initialiser Express
const app = express();

//initialiser websocket
const server = require('http').createServer(app);
const wss = new WebSocket.Server({ server });

// Middlewares
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
//app.use('/api', videoRoutes);

// Initialiser Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

// Stockage temporaire des OTPs
const otpStorage = {};

//Initialisation des catégories du quiz dans le backend
exports.initializeCategories = async (req, res) => {
  try {
    const categories = [
      { titre: 'Développement Web', icon: 'web', description: 'Quiz sur le développement web' },
      { titre: 'Comptabilité', icon: 'calculate', description: 'Quiz sur la comptabilité' },
      { titre: 'Data Science', icon: 'science', description: 'Quiz sur la data science' },
      { titre: 'Marketing Digital', icon: 'campaign', description: 'Quiz sur le marketing digital' },
      { titre: 'Finance', icon: 'account_balance', description: 'Quiz sur la finance' },
      { titre: 'Design Graphique', icon: 'brush', description: 'Quiz sur le design graphique' },
    ];

    for (const category of categories) {
      const categoryRef = await db.collection('CategorieQuiz').add({
        titre: category.titre,
        description: category.description,
        auteur: 'admin', // Remplace par un ID utilisateur réel ou laisse vide pour l’instant
        date_creation: admin.firestore.FieldValue.serverTimestamp(),
        icon: category.icon,
      });
      console.log(`Catégorie ${category.titre} créée avec l’ID ${categoryRef.id}`);
    }

    res.status(200).json({ message: 'Catégories initialisées avec succès' });
  } catch (error) {
    console.error('Erreur lors de l’initialisation des catégories:', error);
    res.status(500).json({ error: 'Erreur lors de l’initialisation des catégories' });
  }
};


wss.on('connection', (ws) => {
  console.log('Client connected');

  ws.on('message', async (message) => {
    const data = JSON.parse(message);
    if (data.type === 'message') {
      const { chatId, sender, content, contentType, timestamp } = data;
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ type: 'message', chatId, sender, content, contentType, timestamp }));
        }
      });
    } else if (data.type === 'invitation') {
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({ type: 'invitation', to: data.to }));
        }
      });
    }
  });

  ws.on('close', () => console.log('Client disconnected'));
});


// Route 1 : Envoyer OTP par email avec vérification reCAPTCHA
app.post('/send-email', async (req, res) => {
  const { to, recaptchaToken } = req.body;
  
  if (!to) return res.status(400).json({ error: "Email requis." });
  if (!recaptchaToken) return res.status(400).json({ error: "Token reCAPTCHA requis." });

  try {
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;
    const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaToken}`;
    const recaptchaResponse = await axios.post(verificationUrl);
    if (!recaptchaResponse.data.success) {
      return res.status(400).json({ error: "La vérification reCAPTCHA a échoué." });
    }
  } catch (error) {
    console.error("Erreur lors de la vérification reCAPTCHA :", error);
    return res.status(500).json({ error: "Erreur lors de la vérification reCAPTCHA." });
  }

  const otp = Math.floor(100000 + Math.random() * 900000);
  otpStorage[to] = otp;

  try {
    let transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });

    let mailOptions = {
      from: `"Edu Hub" <${process.env.GMAIL_USER}>`,
      to: to,
      subject: 'Votre code OTP',
      text: `Bonjour,\n\nVotre code OTP est : ${otp}\n\nMerci d'utiliser Edu Hub.`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Email OTP envoyé à ${to}`);
    res.status(200).json({ message: 'OTP envoyé avec succès !' });
  } catch (error) {
    console.error("❌ Erreur lors de l'envoi de l'email :", error);
    res.status(500).json({ error: 'Erreur lors de l\'envoi de l\'OTP' });
  }
});

// Route 2 : Vérifier OTP et enregistrer l'utilisateur
app.post('/verify-otp', async (req, res) => {
  const { firstName, lastName, email, password, otp, role } = req.body;

  if (!firstName || !lastName || !email || !password || !otp || !role) {
    return res.status(400).json({ error: "Tous les champs sont requis." });
  }

  if (otpStorage[email] !== parseInt(otp)) {
    return res.status(400).json({ error: "OTP invalide ou expiré." });
  }

  delete otpStorage[email];

  try {
    const userRef = db.collection('users').doc(email);
    const userSnapshot = await userRef.get();

    if (userSnapshot.exists) {
      return res.status(400).json({ error: "L'utilisateur existe déjà." });
    }

    const hashedPassword = await User.hashPassword(password);
    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      role,
      preferredDomains: [],
      learningResources: [],
      bio: '',
      competences: [],
      isProfileComplete: false,
      isTeacherVerified: false,
    });
    
    const userData = newUser.toObject();
    await userRef.set(userData);

    console.log(`✅ Utilisateur ${email} enregistré avec succès !`);
    res.status(200).json({ message: "Utilisateur enregistré avec succès !" });
  } catch (error) {
    console.error("❌ Erreur lors de l'enregistrement de l'utilisateur :", error);
    res.status(500).json({ error: "Erreur lors de l'enregistrement de l'utilisateur." });
  }
});

// Route 3 : Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis." });
  }

  try {
    const userRef = db.collection('users').doc(email);
    const userSnapshot = await userRef.get();

    if (!userSnapshot.exists) {
      return res.status(400).json({ error: "Utilisateur introuvable." });
    }

    const userData = userSnapshot.data();
    const isMatch = await User.comparePassword(password, userData.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Mot de passe incorrect." });
    }

    return res.status(200).json({ message: "Connexion réussie !" });
  } catch (error) {
    console.error("❌ Erreur lors de la connexion :", error);
    res.status(500).json({ error: "Erreur serveur lors de la connexion." });
  }
});

// Route pour uploader les documents de vérification pour les enseignants
app.post('/upload-teacher-documents', upload.fields([
  { name: 'idCardFront', maxCount: 1 },
  { name: 'idCardBack', maxCount: 1 },
  { name: 'verificationDocuments', maxCount: 5 },
]), async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email requis." });

  try {
    const userRef = db.collection('users').doc(email);
    const userSnapshot = await userRef.get();
    if (!userSnapshot.exists) return res.status(400).json({ error: "Utilisateur introuvable." });
    
    const idCardFrontFile = req.files['idCardFront'] ? req.files['idCardFront'][0].path : null;
    const idCardFrontUpload = idCardFrontFile ? await cloudinary.uploader.upload(idCardFrontFile, { access_mode: 'public' }) : null;
    
    const idCardBackFile = req.files['idCardBack'] ? req.files['idCardBack'][0].path : null;
    const idCardBackUpload = idCardBackFile ? await cloudinary.uploader.upload(idCardBackFile, { access_mode: 'public' }) : null;
    
    const verificationDocumentsUploads = [];
    if (req.files['verificationDocuments']) {
      for (let file of req.files['verificationDocuments']) {
        const uploadResponse = await cloudinary.uploader.upload(file.path, { access_mode: 'public' });
        verificationDocumentsUploads.push(uploadResponse.secure_url);
      }
    }

    await userRef.update({
      idCardFront: idCardFrontUpload ? idCardFrontUpload.secure_url : null,
      idCardBack: idCardBackUpload ? idCardBackUpload.secure_url : null,
      verificationDocuments: verificationDocumentsUploads,
      isTeacherVerified: false,
      updatedAt: new Date(),
    });

    console.log(`✅ Documents de vérification mis à jour pour ${email}`);
    res.status(200).json({ message: "Documents envoyés avec succès." });
  } catch (error) {
    console.error("❌ Erreur lors de l'upload des documents enseignant :", error);
    res.status(500).json({ error: "Erreur lors de l'upload des documents." });
  }
});

// Route : Récupérer les enseignants en attente de vérification
app.get('/pending-teachers', async (req, res) => {
  try {
    const snapshot = await db.collection('users')
      .where('isTeacherVerified', '==', false)
      .where('role', '==', 'Enseignant')
      .get();

    const users = [];
    snapshot.forEach(doc => users.push({ id: doc.id, ...doc.data() }));
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ error: "Erreur de récupération des données" });
  }
});

// Route : Approuver un enseignant
app.post('/approve-teacher', async (req, res) => {
  const { email } = req.body;
  try {
    await db.collection('users').doc(email).update({
      isTeacherVerified: true,
      updatedAt: new Date(),
    });
    res.status(200).json({ message: "Enseignant approuvé" });
  } catch (error) {
    res.status(500).json({ error: "Erreur lors de l'approbation" });
  }
});

// Route : Récupérer un utilisateur par email
app.post('/get-user', async (req, res) => {
  const { email } = req.body;
  try {
    const doc = await db.collection('users').doc(email).get();
    if (doc.exists) {
      res.status(200).json({ id: doc.id, ...doc.data() });
    } else {
      res.status(404).json({ error: "Utilisateur non trouvé" });
    }
  } catch (error) {
    res.status(500).json({ error: "Erreur de récupération" });
  }
});

// Endpoint pour interroger l'API Vimeo
// Endpoint pour interroger l'API Vimeo
// app.get('/resources', async (req, res) => {
//   const domainsParam = req.query.domains;
//   let domains = domainsParam ? domainsParam.split(',') : [];
//   const query = domains.length > 0 ? domains[0] : ''; // Prendre le premier domaine pour la recherche

//   try {
//     const apiToken = process.env.VIMEO_API_TOKEN;
//     if (!apiToken) {
//       console.error("❌ Token Vimeo non défini dans les variables d'environnement");
//       return res.status(500).json({ error: "Configuration serveur incorrecte" });
//     }

//     const response = await axios.get('https://api.vimeo.com/videos', {
//       headers: {
//         Authorization: `Bearer ${apiToken}`,
//       },
//       params: {
//         query: `${query} tutorial`,
//         per_page: 20, // Réduire à 10 pour accélérer la réponse
//         sort: 'relevant',
//       },
//       timeout: 10000, // Timeout de 10 secondes pour éviter les attentes infinies
//     }).catch(error => {
//       if (error.code === 'ENOTFOUND') {
//         throw new Error('Impossible de résoudre api.vimeo.com - Vérifiez la connexion réseau');
//       } else if (error.code === 'ECONNABORTED') {
//         throw new Error('Délai de réponse dépassé pour Vimeo');
//       } else {
//         throw error;
//       }
//     });

//     const videos = response.data.data.map(video => ({
//       domain: query,
//       title: video.name,
//       source: 'Vimeo',
//       type: 'video',
//       link: video.link,
//       thumbnail: video.pictures.sizes[2]?.link || 'https://via.placeholder.com/150',
//       description: video.description || 'Pas de description disponible',
//     }));

//     console.log(`✅ Ressources Vimeo récupérées pour le domaine : ${query} (${videos.length} vidéos)`);
//     res.status(200).json(videos);
//   } catch (error) {
//     console.error("❌ Erreur lors de la recherche Vimeo: ", error.message || error);
//     res.status(500).json({ error: "Erreur lors de la recherche des ressources", details: error.message });
//   }
// });

// Endpoint pour interroger l'API YouTube (remplace Vimeo)
// Endpoint pour interroger l'API YouTube (remplace Vimeo)
app.get('/resources', async (req, res) => {
  const domainsParam = req.query.domains;
  let domains = domainsParam ? domainsParam.split(',') : [];
  const query = domains.length > 0 ? domains[0] : ''; // Prendre le premier domaine pour la recherche

  try {
    const apiKey = process.env.YOUTUBE_API_KEY;
    if (!apiKey) {
      console.error("❌ Clé API YouTube non définie dans les variables d'environnement");
      return res.status(500).json({ error: "Configuration serveur incorrecte" });
    }

    const response = await axios.get('https://www.googleapis.com/youtube/v3/search', {
      params: {
        part: 'snippet',
        q: `${query} tutorial`, // Recherche avec le domaine + "tutorial"
        type: 'video',
        maxResults: 10, // Limité à 10 pour performances
        key: apiKey,
      },
      timeout: 10000, // Timeout de 10 secondes
    }).catch(error => {
      if (error.code === 'ENOTFOUND') {
        throw new Error('Impossible de résoudre www.googleapis.com - Vérifiez la connexion réseau');
      } else if (error.code === 'ECONNABORTED') {
        throw new Error('Délai de réponse dépassé pour YouTube');
      } else {
        throw error;
      }
    });

    const videos = response.data.items.map(item => ({
      domain: query,
      title: item.snippet.title,
      source: 'YouTube',
      type: 'video',
      link: `https://www.youtube.com/watch?v=${item.id.videoId}`, // URL de la vidéo
      thumbnail: item.snippet.thumbnails.medium.url || 'https://via.placeholder.com/150', // Thumbnail moyen
      description: item.snippet.description || 'Pas de description disponible',
    }));

    console.log(`✅ Ressources YouTube récupérées pour le domaine : ${query} (${videos.length} vidéos)`);
    res.status(200).json(videos);

    /*
    // Logique Vimeo mise en commentaire
    const apiToken = process.env.VIMEO_API_TOKEN;
    if (!apiToken) {
      console.error("❌ Token Vimeo non défini dans les variables d'environnement");
      return res.status(500).json({ error: "Configuration serveur incorrecte" });
    }

    const response = await axios.get('https://api.vimeo.com/videos', {
      headers: {
        Authorization: `Bearer ${apiToken}`,
      },
      params: {
        query: `${query} tutorial`,
        per_page: 10,
        sort: 'relevant',
      },
      timeout: 10000,
    }).catch(error => {
      if (error.code === 'ENOTFOUND') {
        throw new Error('Impossible de résoudre api.vimeo.com - Vérifiez la connexion réseau');
      } else if (error.code === 'ECONNABORTED') {
        throw new Error('Délai de réponse dépassé pour Vimeo');
      } else {
        throw error;
      }
    });

    const videos = response.data.data.map(video => ({
      domain: query,
      title: video.name,
      source: 'Vimeo',
      type: 'video',
      link: video.link,
      thumbnail: video.pictures.sizes[2]?.link || 'https://via.placeholder.com/150',
      description: video.description || 'Pas de description disponible',
    }));

    console.log(`✅ Ressources Vimeo récupérées pour le domaine : ${query} (${videos.length} vidéos)`);
    res.status(200).json(videos);
    */
  } catch (error) {
    console.error("❌ Erreur lors de la recherche YouTube: ", error.message || error);
    res.status(500).json({ error: "Erreur lors de la recherche des ressources", details: error.message });
  }
});

// Endpoint pour mettre à jour les informations du profil utilisateur
app.post('/update-user', async (req, res) => {
  const { email, firstName, lastName, bio, competences } = req.body;
  if (!email) return res.status(400).json({ error: "Email requis." });

  const updateData = {};
  if (firstName) updateData.firstName = firstName;
  if (lastName) updateData.lastName = lastName;
  if (bio) updateData.bio = bio;
  if (competences) updateData.competences = competences;
  updateData.updatedAt = new Date();

  try {
    await db.collection('users').doc(email).update(updateData);
    res.status(200).json({ message: "Profil mis à jour avec succès." });
  } catch (error) {
    console.error("❌ Erreur lors de la mise à jour du profil:", error);
    res.status(500).json({ error: "Erreur lors de la mise à jour du profil." });
  }
});

// Endpoint pour enregistrer une ressource pédagogique
app.post('/upload-resource', upload.single('file'), async (req, res) => {
  const { type, title, description, domain, isPaid, price, uploadedBy, courseId } = req.body;
  if (!type || !title || !description || !domain || !uploadedBy) {
    return res.status(400).json({ error: "Tous les champs requis doivent être renseignés." });
  }

  const paid = isPaid === 'true';
  const resourcePrice = paid ? Number(price) : 0;
  let resourceId;

  try {
    if (type === 'Cours') {
      const courseData = {
        title,
        description,
        domain,
        teacherId: uploadedBy,
        isPaid: paid,
        price: resourcePrice,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const courseRef = await db.collection('courses').add(courseData);
      resourceId = courseRef.id;
    } else if (type === 'Document') {
      if (!req.file) return res.status(400).json({ error: "Fichier requis pour un document." });
      const filePath = req.file.path;
      const uploadResponse = await cloudinary.uploader.upload(filePath, {
        resource_type: 'auto',
        access_mode: 'public', // Force l'accès public
      });
      console.log(`✅ Document uploadé sur Cloudinary : ${uploadResponse.secure_url}`);
      const documentData = {
        title,
        description,
        domain,
        fileUrl: uploadResponse.secure_url,
        thumbnail: uploadResponse.secure_url,
        uploadedBy,
        isPaid: paid,
        price: resourcePrice,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const docRef = await db.collection('documents').add(documentData);
      resourceId = docRef.id;
    } else if (type === 'Exercice') {
      const exerciseData = {
        title,
        content: description,
        domain,
        courseId: courseId || null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const exRef = await db.collection('exercises').add(exerciseData);
      resourceId = exRef.id;
    } else {
      return res.status(400).json({ error: "Type de ressource non supporté." });
    }

    console.log(`✅ Ressource ${type} créée avec ID: ${resourceId}`);

    const studentsQuery = await db.collection('users')
      .where('role', 'in', ['Etudiant', 'Autodidacte'])
      .where('preferredDomains', 'array-contains', domain)
      .get();

    for (const studentDoc of studentsQuery.docs) {
      const studentEmail = studentDoc.id;
      const notificationRef = db.collection('notifications').doc(studentEmail);
      await notificationRef.set({
        unreadResources: admin.firestore.FieldValue.arrayUnion({
          resourceId,
          type,
          domain,
          title,
          uploadedAt: new Date(),
        }),
      }, { merge: true });
    }

    return res.status(200).json({ message: `${type} créé avec succès.` });
  } catch (error) {
    console.error("❌ Erreur lors de l'enregistrement de la ressource:", error);
    return res.status(500).json({ error: "Erreur lors de l'enregistrement de la ressource." });
  }
});

app.get('/student-resources', async (req, res) => {
  const { email } = req.query;
  console.log(`✅ Récupération des ressources pour l'étudiant: ${email}`);
  if (!email) return res.status(400).json({ error: "Email requis." });

  try {
    const userRef = db.collection('users').doc(email);
    const userSnapshot = await userRef.get();
    if (!userSnapshot.exists) return res.status(404).json({ error: "Utilisateur non trouvé" });
    
    const userData = userSnapshot.data();
    const preferredDomains = userData.preferredDomains || [];

    const teachersQuery = await db.collection('users')
      .where('role', '==', 'Enseignant')
      .where('preferredDomains', 'array-contains-any', preferredDomains)
      .get();
    const teacherIds = teachersQuery.docs.map(doc => doc.id);

    if (teacherIds.length === 0) return res.status(200).json([]);

    const coursesQuery = await db.collection('courses')
      .where('teacherId', 'in', teacherIds)
      .where('domain', 'in', preferredDomains)
      .get();
    const documentsQuery = await db.collection('documents')
      .where('uploadedBy', 'in', teacherIds)
      .where('domain', 'in', preferredDomains)
      .get();

    const resources = [
      ...coursesQuery.docs.map(doc => ({ id: doc.id, type: 'Cours', ...doc.data() })),
      ...documentsQuery.docs.map(doc => ({ id: doc.id, type: 'Document', ...doc.data() })),
    ];

    console.log(`✅ Domaines préférés: ${preferredDomains}, Ressources récupérées: ${resources.length}`);
    res.status(200).json(resources);
  } catch (error) {
    console.error("❌ Erreur lors de la récupération des ressources:", error);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// Route : Récupérer les statistiques globales pour le dashboard admin
app.get('/statistics', async (req, res) => {
  try {
    // Compter le nombre d'étudiants
    const etudiantsSnapshot = await db.collection('users')
      .where('role', '==', 'Étudiant')
      .get();
      
    // Compter le nombre d'enseignants
    const enseignantsSnapshot = await db.collection('users')
      .where('role', '==', 'Enseignant')
      .get();
      
    // Compter le nombre d'autodidactes
    const autodidactesSnapshot = await db.collection('users')
      .where('role', '==', 'Autodidacte')
      .get();
      
    // Compter le nombre de demandes en attente (enseignants non vérifiés)
    const pendingSnapshot = await db.collection('users')
      .where('role', '==', 'Enseignant')
      .where('isTeacherVerified', '==', false)
      .get();
      
    res.status(200).json({
      etudiants: etudiantsSnapshot.size,
      enseignants: enseignantsSnapshot.size,
      autodidactes: autodidactesSnapshot.size,
      pendingRequests: pendingSnapshot.size,
    });
  } catch (error) {
    console.error("Erreur lors de la récupération des statistiques:", error);
    res.status(500).json({ error: "Erreur lors de la récupération des statistiques." });
  }
});


// Route pour créer un questionnaire (quiz)
app.post('/api/questionnaires', async (req, res) => {
  const { titre, description, niveau, categorie, auteur } = req.body;

  if (!titre || !niveau || !categorie) {
    return res.status(400).json({ error: "Titre, niveau et catégorie sont requis." });
  }

  try {
    // Vérifier si la catégorie existe
    const categorySnapshot = await db.collection('CategorieQuiz')
      .where('titre', '==', categorie)
      .get();

    if (categorySnapshot.empty) {
      return res.status(404).json({ error: "Catégorie non trouvée." });
    }

    const categoryDoc = categorySnapshot.docs[0];
    const categoryRef = db.doc(`CategorieQuiz/${categoryDoc.id}`);

    // Créer le questionnaire
    const questionnaireRef = await db.collection('Questionnaire').add({
      titre: titre,
      description: description || '',
      categorie: categoryRef,
      niveau: niveau,
      niveau_suivant: null, // À définir plus tard si nécessaire
      date_creation: admin.firestore.FieldValue.serverTimestamp(),
      update: admin.firestore.FieldValue.serverTimestamp(),
      auteur: auteur || 'admin', // Remplace par l’ID de l’utilisateur connecté (par exemple, email)
    });

    console.log(`✅ Questionnaire ${titre} créé avec succès avec l’ID ${questionnaireRef.id}`);
    res.status(201).json({ message: "Questionnaire créé avec succès !" });
  } catch (error) {
    console.error("❌ Erreur lors de la création du questionnaire :", error);
    res.status(500).json({ error: "Erreur lors de la création du questionnaire." });
  }
});

// Route pour récupérer les catégories (pour le dropdown dans Flutter)
app.get('/api/categories', async (req, res) => {
  try {
    const snapshot = await db.collection('CategorieQuiz').get();
    const categories = snapshot.docs.map(doc => ({
      id: doc.id,
      titre: doc.data().titre,
      icon: doc.data().icon, // Pour mapper les icônes dans Flutter
      description: doc.data().description,
    }));
    console.log(`✅ Catégories récupérées avec succès : ${categories.length} catégories`);
    res.status(200).json(categories);
  } catch (error) {
    console.error("❌ Erreur lors de la récupération des catégories :", error);
    res.status(500).json({ error: "Erreur lors de la récupération des catégories." });
  }
});


// Route pour créer un quiz, une question et ses choix simultanément
// Route pour créer un quiz, une question et ses choix simultanément, en gérant dynamiquement les catégories
app.post('/api/create-quiz-with-question', async (req, res) => {
  const { quiz, question, choices } = req.body;

  if (!quiz.titre || !quiz.niveau || !quiz.categorie || !question.texte || !choices || choices.length < 2) {
    return res.status(400).json({ error: "Tous les champs requis doivent être remplis, et au moins 2 choix doivent être fournis." });
  }

  // Vérifier qu’au moins un choix est marqué comme correct
  if (!choices.some(choice => choice.isCorrect)) {
    return res.status(400).json({ error: "Un choix correct doit être sélectionné." });
  }

  try {
    // Normaliser la catégorie pour éviter les problèmes de casse et d’espaces
    const normalizedCategory = quiz.categorie.trim().toLowerCase();
    let categoryRef;

    // Vérifier si la collection CategorieQuiz existe
    const categoriesSnapshot = await db.listCollections();
    const categoryCollectionExists = categoriesSnapshot.some(collection => collection.id === 'CategorieQuiz');

    if (categoryCollectionExists) {
      console.log(`✅ Collection CategorieQuiz existe déjà`);

      // Vérifier si la catégorie existe dans la collection
      const categorySnapshot = await db.collection('CategorieQuiz')
        .where('titre', '==', quiz.categorie) // Utiliser la catégorie telle que reçue pour l’instant
        .get();

      if (categorySnapshot.empty) {
        // Si la catégorie n’existe pas, la créer
        const newCategoryRef = await db.collection('CategorieQuiz').add({
          titre: quiz.categorie,
          description: '', // Description facultative, à définir si nécessaire
          auteur: quiz.auteur || 'admin', // Remplace par l’ID de l’utilisateur connecté
          date_creation: admin.firestore.FieldValue.serverTimestamp(),
          icon: '', // Icône facultative, à définir si nécessaire (par exemple, basé sur quiz.categorie)
        });
        console.log(`✅ Nouvelle catégorie ${quiz.categorie} créée avec l’ID ${newCategoryRef.id}`);
        categoryRef = newCategoryRef;
      } else {
        // Si la catégorie existe, utiliser la référence existante
        const categoryDoc = categorySnapshot.docs[0];
        categoryRef = db.doc(`CategorieQuiz/${categoryDoc.id}`);
        console.log(`✅ Catégorie ${quiz.categorie} trouvée avec l’ID ${categoryDoc.id}`);
      }
    } else {
      // Si la collection n’existe pas, la créer et ajouter la catégorie
      console.log(`✅ Création de la collection CategorieQuiz`);
      const newCategoryRef = await db.collection('CategorieQuiz').add({
        titre: quiz.categorie,
        description: '', // Description facultative
        auteur: quiz.auteur || 'admin', // Remplace par l’ID de l’utilisateur connecté
        date_creation: admin.firestore.FieldValue.serverTimestamp(),
        icon: '', // Icône facultative
      });
      console.log(`✅ Nouvelle catégorie ${quiz.categorie} créée avec l’ID ${newCategoryRef.id}`);
      categoryRef = newCategoryRef;
    }

    // Créer le questionnaire
    const questionnaireRef = await db.collection('Questionnaire').add({
      titre: quiz.titre,
      description: quiz.description || '',
      categorie: categoryRef,
      niveau: quiz.niveau,
      niveau_suivant: null, // À définir plus tard si nécessaire
      date_creation: admin.firestore.FieldValue.serverTimestamp(),
      update: admin.firestore.FieldValue.serverTimestamp(),
      auteur: quiz.auteur || 'admin', // Remplace par l’ID de l’utilisateur connecté
    });

    console.log(`✅ Questionnaire ${quiz.titre} créé avec succès avec l’ID ${questionnaireRef.id}`);

    // Créer la question associée au questionnaire
    const questionRef = await db.collection('Question').add({
      texte: question.texte,
      questionnaire: db.doc(`Questionnaire/${questionnaireRef.id}`),
    });

    console.log(`✅ Question créée avec succès avec l’ID ${questionRef.id}`);

    // Créer les choix associés à la question
    for (const choice of choices) {
      await db.collection('Choix').add({
        texte: choice.text,
        est_correct: choice.isCorrect,
        question: db.doc(`Question/${questionRef.id}`),
      });
    }

    console.log(`✅ Choix créés avec succès pour la question ${questionRef.id}`);
    res.status(201).json({ message: "Quiz, question et choix créés avec succès !" });
  } catch (error) {
    console.error("❌ Erreur lors de la création du quiz, question et choix :", error);
    res.status(500).json({ error: "Erreur lors de la création du quiz, question et choix." });
  }
});


//route pour les resultat du quiz
app.post('/api/save-quiz-result', async (req, res) => {
  const { user, categorie, niveau, score, score_cat, termine } = req.body;

  if (!user || !categorie || !niveau || score == null) {
    return res.status(400).json({ error: "Tous les champs requis doivent être remplis." });
  }

  try {
    // Vérifier si la catégorie existe ou la créer (similaire à la logique précédente)
    const categorySnapshot = await db.collection('CategorieQuiz')
      .where('titre', '==', categorie)
      .get();

    let categoryRef;
    if (categorySnapshot.empty) {
      const newCategoryRef = await db.collection('CategorieQuiz').add({
        titre: categorie,
        description: '',
        auteur: user, // Utilisateur qui joue au quiz
        date_creation: admin.firestore.FieldValue.serverTimestamp(),
        icon: '', // Icône facultative
      });
      console.log(`✅ Nouvelle catégorie ${categorie} créée avec l’ID ${newCategoryRef.id}`);
      categoryRef = newCategoryRef;
    } else {
      const categoryDoc = categorySnapshot.docs[0];
      categoryRef = db.doc(`CategorieQuiz/${categoryDoc.id}`);
      console.log(`✅ Catégorie ${categorie} trouvée avec l’ID ${categoryDoc.id}`);
    }

    // Créer le résultat
    const resultRef = await db.collection('ResultatQuiz').add({
      user: user, // Email ou ID de l’utilisateur
      categorie: categoryRef,
      niveau: niveau,
      score: score,
      score_cat: score_cat || 0,
      termine: termine || true,
      date_passage: admin.firestore.FieldValue.serverTimestamp(),
    });

    console.log(`✅ Résultat du quiz enregistré pour l’utilisateur ${user} avec l’ID ${resultRef.id}`);
    res.status(201).json({ message: "Résultat du quiz enregistré avec succès !" });
  } catch (error) {
    console.error("❌ Erreur lors de l’enregistrement du résultat du quiz :", error);
    res.status(500).json({ error: "Erreur lors de l’enregistrement du résultat du quiz." });
  }
});



// Route pour récupérer un classement global par catégorie avec scores agrégés
app.get('/api/leaderboard', async (req, res) => {
  const { email } = req.query;
  if (!email) {
    return res.status(400).json({ error: "Email requis." });
  }

  try {
    // Vérifier l'utilisateur (juste pour s'assurer qu'il existe)
    const userSnapshot = await db.collection('users').doc(email).get();
    if (!userSnapshot.exists) {
      return res.status(404).json({ error: "Utilisateur non trouvé." });
    }

    const userData = userSnapshot.data();
    const preferredDomains = userData.preferredDomains || [];

    if (preferredDomains.length === 0) {
      return res.status(200).json({ message: "Aucun domaine préféré trouvé.", leaderboard: {} });
    }

    const leaderboard = {};
    for (const domain of preferredDomains) {
      // Trouver la catégorie correspondante
      const categorySnapshot = await db.collection('CategorieQuiz')
        .where('titre', '==', domain)
        .get();

      if (categorySnapshot.empty) {
        leaderboard[domain] = [];
        continue;
      }

      const categoryRef = categorySnapshot.docs[0].ref;
      const resultsSnapshot = await db.collection('ResultatQuiz')
        .where('categorie', '==', categoryRef)
        .get();

      // Regrouper les résultats par utilisateur
      const userScores = {};
      resultsSnapshot.forEach(doc => {
        const data = doc.data();
        const userEmail = data.user;

        if (!userScores[userEmail]) {
          userScores[userEmail] = {
            scores: [],
            niveauMax: 0,
            latestDate: null,
          };
        }

        // Ajouter le score à la liste
        const score = data.score_cat || data.score || 0;
        userScores[userEmail].scores.push(score);
        // Mettre à jour le niveau max si applicable
        if (data.niveau > userScores[userEmail].niveauMax) {
          userScores[userEmail].niveauMax = data.niveau;
        }
        // Mettre à jour la date la plus récente
        const date = data.date_passage?.toDate() || new Date();
        if (!userScores[userEmail].latestDate || date > userScores[userEmail].latestDate) {
          userScores[userEmail].latestDate = date;
        }
      });

      // Calculer un score agrégé pour chaque utilisateur (moyenne ici, mais tu peux changer)
      const results = [];
      for (const userEmail in userScores) {
        const scores = userScores[userEmail].scores;
        const averageScore = scores.reduce((a, b) => a + b, 0) / scores.length; // Moyenne
        // Alternative : const bestScore = Math.max(...scores); // Meilleur score

        results.push({
          user: userEmail,
          score: averageScore.toFixed(1), // Score moyen arrondi à 1 décimale
          niveau: userScores[userEmail].niveauMax,
          date: userScores[userEmail].latestDate.toISOString(),
          gamesPlayed: scores.length, // Nombre de parties jouées
        });
      }

      // Trier par score décroissant
      results.sort((a, b) => b.score - a.score);
      leaderboard[domain] = results;
    }

    console.log(`✅ Classements agrégés récupérés pour ${email} : ${JSON.stringify(leaderboard)}`);
    res.status(200).json({ message: "Classements récupérés avec succès.", leaderboard });
  } catch (error) {
    console.error("❌ Erreur lors de la récupération des classements :", error);
    res.status(500).json({ error: "Erreur lors de la récupération des classements." });
  }
});


//Ajoute une logique pour considérer les utilisateurs comme déconnectés si lastSeen est trop ancien 
app.get('/online-users', async (req, res) => {
  try {
    const snapshot = await db.collection('users').get();
    const threshold = new Date(Date.now() - 60 * 1000); // 60 secondes d'inactivité
    const onlineUsers = snapshot.docs
      .map(doc => ({
        email: doc.id,
        ...doc.data(),
      }))
      .filter(user => {
        const lastSeen = user.lastSeen ? user.lastSeen.toDate() : null;
        return lastSeen && lastSeen > threshold;
      });
    res.status(200).json(onlineUsers);
  } catch (error) {
    console.error('Erreur lors de la récupération des utilisateurs en ligne :', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// Route pour uploader un lien vidéo
app.post('/api/upload-video-link', async (req, res) => {
  const { email, domain, videoUrl, title, description } = req.body;

  if (!email || !domain || !videoUrl) {
    return res.status(400).json({ error: 'Email, domaine et URL sont requis.' });
  }

  if (!videoUrl.startsWith('http')) {
    return res.status(400).json({ error: 'URL invalide.' });
  }

  try {
    const userRef = db.collection('users').doc(email);
    const userSnapshot = await userRef.get();
    if (!userSnapshot.exists || userSnapshot.data().role !== 'Enseignant') {
      return res.status(403).json({ error: 'Utilisateur non autorisé ou non trouvé.' });
    }

    const videoData = {
      email,
      domain,
      url: videoUrl,
      type: 'link',
      title: title || '',
      description: description || '',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      status: 'approved',
      duration: null,
      thumbnail: null,
    };

    const videoRef = await db.collection('videos').add(videoData);
    console.log(`✅ Lien vidéo enregistré avec l’ID ${videoRef.id} pour ${email}`);

    res.status(201).json({
      message: 'Lien enregistré avec succès',
      videoId: videoRef.id,
      url: videoUrl,
    });
  } catch (error) {
    console.error('❌ Erreur lors de l’enregistrement du lien vidéo :', error);
    res.status(500).json({ error: 'Erreur serveur lors de l’enregistrement du lien.' });
  }
});

// Route pour uploader un fichier vidéo
app.post('/api/upload-video-file', upload.single('video'), async (req, res) => {
  const { email, domain, title, description } = req.body;

  if (!email || !domain) {
    return res.status(400).json({ error: 'Email et domaine sont requis.' });
  }
  if (!req.file) {
    return res.status(400).json({ error: 'Aucun fichier vidéo fourni.' });
  }

  try {
    const userRef = db.collection('users').doc(email);
    const userSnapshot = await userRef.get();
    if (!userSnapshot.exists || userSnapshot.data().role !== 'Enseignant') {
      return res.status(403).json({ error: 'Utilisateur non autorisé ou non trouvé.' });
    }

    const result = await cloudinary.uploader.upload(req.file.path, {
      resource_type: 'video',
      folder: 'edu_hub_videos',
      access_mode: 'public',
    });

    const videoData = {
      email,
      domain,
      url: result.secure_url,
      type: 'file',
      title: title || '',
      description: description || '',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      status: 'pending',
      duration: result.duration || null,
      thumbnail: result.thumbnail_url || null,
    };

    const videoRef = await db.collection('videos').add(videoData);
    console.log(`✅ Vidéo uploadée avec l’ID ${videoRef.id} pour ${email}`);

    require('fs').unlinkSync(req.file.path);

    res.status(201).json({
      message: 'Vidéo uploadée avec succès',
      videoId: videoRef.id,
      url: result.secure_url,
    });
  } catch (error) {
    console.error('❌ Erreur lors de l’upload de la vidéo :', error);
    res.status(500).json({ error: 'Erreur serveur lors de l’upload de la vidéo.' });
  }
});

// Démarrer le serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`));