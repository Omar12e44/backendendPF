require("dotenv").config(); // Carga las variables de entorno
const express = require("express");
const speakeasy = require("speakeasy");
const bcrypt = require("bcrypt");
const cors = require("cors");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const fs = require("fs");

// Inicializa Firebase Admin usando variables de entorno
admin.initializeApp({
  credential: admin.credential.cert({
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: process.env.FIREBASE_AUTH_URI,
    token_uri: process.env.FIREBASE_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
    universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN,
  }),
});
const db = admin.firestore();
console.log("Conexión a Firebase Firestore establecida correctamente");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: 'omarbasal18@gmail.com',
    pass: 'kzeafdgrsjvpfpkm'
}
});

const generateRandomPassword = () => {
  return Math.random().toString(36).slice(-8); // Genera una contraseña aleatoria de 8 caracteres
};



const app = express();
app.use(cors());
app.use(bodyParser.json());

// Registro de usuarios
// Registro de usuarios
app.post("/register", async (req, res) => {
  const { email, password, name, phone, address } = req.body; // Agregar nuevos campos
  const hashedPassword = await bcrypt.hash(password, 10);

  const secret = speakeasy.generateSecret({ length: 20 });
  const user = {
    email,
    password: hashedPassword,
    name, // Guardar el nombre
    phone, // Guardar el teléfono
    address, // Guardar la dirección
    secret: secret.base32,
  };

  try {
    await db.collection("users").doc(email).set(user); // Guarda el usuario en Firestore
    res.json({ secret: secret.otpauth_url }); // URL correcta para Google Authenticator
  } catch (error) {
    console.error("Error al registrar usuario:", error);
    res.status(500).json({ error: "Error al registrar usuario" });
  }
});

// Login de usuarios
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Buscar el usuario en Firestore
    const userDoc = await db.collection("users").doc(email).get();
    if (!userDoc.exists) {
      return res.status(401).json({ error: "Email o contraseña inválida" });
    }

    const user = userDoc.data();

    // Comparar la contraseña ingresada con la hasheada
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Email o contraseña inválida" });
    }

    // Generar un token JWT
    const token = jwt.sign(
      { email: user.email }, // Payload del token
      process.env.JWT_SECRET, // Clave secreta (debe estar en las variables de entorno)
      { expiresIn: "1h" } // Tiempo de expiración del token
    );

    // Respuesta exitosa con el token
    res.json({ message: "Inicio de sesión exitoso", token,user: {
      email: user.email
    } ,requiresMFA: true });
  } catch (error) {
    console.error("Error durante el inicio de sesión:", error);
    res.status(500).json({ error: "Error durante el inicio de sesión" });
  }
});


app.post("/reset-password", async (req, res) => {
  const { email } = req.body;

  try {
    // Generar nueva contraseña y hashearla
    const newPassword = generateRandomPassword();
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Actualizar la contraseña en Firestore
    const userDoc = await db.collection("users").doc(email).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    await db.collection("users").doc(email).update({ password: hashedPassword });

    // Configurar el correo
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Restablecimiento de contraseña",
      text: `Tu nueva contraseña es: ${newPassword}`,
    };

    // Enviar el correo
    await transporter.sendMail(mailOptions);

    res.json({ message: "Correo de recuperación enviado" });
  } catch (error) {
    console.error("Error al enviar el correo de recuperación:", error);
    res.status(500).json({ message: "No se pudo enviar el correo", error: error.message });
  }
});


// Verificar OTP
app.post("/verify-otp", async (req, res) => {
  const { email, token } = req.body;

  try {
    const userDoc = await db.collection("users").doc(email).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const user = userDoc.data();
    const verified = speakeasy.totp.verify({
      secret: user.secret,
      encoding: "base32",
      token,
      window: 3,
    });

    if (verified) {
      res.json({ message: "OTP verificado correctamente" });
    } else {
      res.status(401).json({ error: "OTP inválido" });
    }
  } catch (error) {
    console.error("Error al verificar OTP:", error);
    res.status(500).json({ error: "Error al verificar OTP" });
  }
});



app.get("/profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1]; // Obtener el token del encabezado Authorization

  if (!token) {
    return res.status(401).json({ error: "Token no proporcionado" });
  }

  try {
    // Verificar el token JWT
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    // Buscar al usuario en Firestore
    const userDoc = await db.collection("users").doc(email).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const user = userDoc.data();

    // Devolver la información del perfil
    res.json({
      email: user.email,
      name: user.name,
      phone: user.phone,
      address: user.address,
      about: user.about,
      experience: user.experience,
      positionsOffered: user.positionsOffered,
      skills: user.skills,
      aptitudes: user.aptitudes,
    });
  } catch (error) {
    console.error("Error al obtener el perfil:", error);
    res.status(500).json({ error: "Error al obtener el perfil" });
  }
});


app.put("/profile_update", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1]; // Obtener el token del encabezado Authorization

  if (!token) {
    return res.status(401).json({ error: "Token no proporcionado" });
  }

  try {
    // Verificar el token JWT
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    // Obtener los datos del cuerpo de la solicitud
    const { name, phone, address, about, experience, positionsOffered, skills, aptitudes } = req.body;

    // Construir el objeto de actualización
    const updates = {};
    if (name) updates.name = name;
    if (phone) updates.phone = phone;
    if (address) updates.address = address;
    if (about) updates.about = about;
    if (experience) updates.experience = experience;
    if (positionsOffered) updates.positionsOffered = positionsOffered;
    if (skills) updates.skills = skills;
    if (aptitudes) updates.aptitudes = aptitudes;

    // Actualizar el documento del usuario en Firestore
    await db.collection("users").doc(email).update(updates);

    res.json({ message: "Perfil actualizado correctamente" });
  } catch (error) {
    console.error("Error al actualizar el perfil:", error);
    res.status(500).json({ error: "Error al actualizar el perfil" });
  }
});

app.get("/categories", async (req, res) => {
  try {
    // Obtener todas las categorías de la colección "categories"
    const categoriesSnapshot = await db.collection("categories").get();

    // Mapear los documentos a un array de objetos
    const categories = categoriesSnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));

    // Enviar las categorías como respuesta
    res.status(200).json(categories);
  } catch (error) {
    console.error("Error al obtener las categorías:", error);
    res.status(500).json({ error: "Error al obtener las categorías." });
  }
});

app.post("/job-offers", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1]; // Obtener el token del encabezado Authorization

  if (!token) {
    return res.status(401).json({ error: "Token no proporcionado" });
  }

  try {
    // Verificar el token JWT
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    // Obtener los datos del cuerpo de la solicitud
    const { title, description, categoryId } = req.body;

    if (!title || !description || !categoryId) {
      return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    // Crear la oferta de trabajo
    const jobOffer = {
      title,
      description,
      categoryId,
      userEmail: email, // Asociar la oferta al usuario autenticado
      createdAt: new Date().toISOString(),
    };

    // Guardar la oferta en Firestore
    const jobOfferRef = await db.collection("jobOffers").add(jobOffer);

    res.status(201).json({ message: "Oferta de trabajo creada correctamente.", id: jobOfferRef.id });
  } catch (error) {
    console.error("Error al crear la oferta de trabajo:", error);
    res.status(500).json({ error: "Error al crear la oferta de trabajo." });
  }
});

app.post("/categories", async (req, res) => {
  const { categories } = req.body; // Recibir un array de categorías desde el cuerpo de la solicitud

  if (!Array.isArray(categories) || categories.length === 0) {
    return res.status(400).json({ error: "Debes proporcionar un array de categorías." });
  }

  try {
    const batch = db.batch(); // Crear una operación en lote para Firestore

    categories.forEach((category) => {
      const docRef = db.collection("categories").doc(); // Crear un nuevo documento para cada categoría
      batch.set(docRef, { name: category }); // Agregar el nombre de la categoría
    });

    await batch.commit(); // Ejecutar la operación en lote

    res.status(201).json({ message: "Categorías agregadas correctamente." });
  } catch (error) {
    console.error("Error al agregar categorías:", error);
    res.status(500).json({ error: "Error al agregar categorías." });
  }
});


         {/* Mostrar el nombre de la categoría */}
         app.get("/job-offers", async (req, res) => {
          try {
            // Obtener todas las categorías
            const categoriesSnapshot = await db.collection("categories").get();
            const categories = categoriesSnapshot.docs.map((doc) => ({
              id: doc.id,
              name: doc.data().name,
            }));
        
            // Crear un mapa de categorías para acceso rápido
            const categoryMap = categories.reduce((map, category) => {
              map[category.id] = category.name;
              return map;
            }, {});
        
            // Obtener todas las ofertas de trabajo
            const jobOffersSnapshot = await db.collection("jobOffers").get();
            const jobOffers = jobOffersSnapshot.docs.map((doc) => ({
              id: doc.id,
              ...doc.data(),
            }));
        
            // Obtener información de los usuarios que crearon las ofertas
            const userIds = [...new Set(jobOffers.map((offer) => offer.userEmail))]; // Obtener correos únicos
            const userDocs = await Promise.all(
              userIds.map(async (email) => {
                const userDoc = await db.collection("users").doc(email).get();
                return userDoc.exists ? { email, ...userDoc.data() } : null;
              })
            );
        
            // Crear un mapa de usuarios para acceso rápido
            const userMap = userDocs.reduce((map, user) => {
              if (user) {
                map[user.email] = user;
              }
              return map;
            }, {});
        
            // Combinar las ofertas con la información de categorías y usuarios
            const enrichedJobOffers = jobOffers.map((offer) => ({
              id: offer.id,
              title: offer.title,
              description: offer.description,
              userEmail: offer.userEmail,
              createdAt: offer.createdAt,
              categoryId: offer.categoryId,
              categoryName: categoryMap[offer.categoryId] || "Categoría desconocida",
              creator: userMap[offer.userEmail] || { name: "Usuario desconocido", email: offer.userEmail },
            }));
        
            res.json(enrichedJobOffers); // Enviar las ofertas enriquecidas
          } catch (error) {
            console.error("Error al obtener las ofertas de trabajo:", error);
            res.status(500).json({ error: "Error al obtener las ofertas de trabajo." });
          }
        });


// Escuchar en el puerto correcto
app.listen(3001, () => {
  console.log("Servidor iniciado en el puerto 3001");
});

