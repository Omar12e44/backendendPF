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

// Escuchar en el puerto correcto
app.listen(3001, () => {
  console.log("Servidor iniciado en el puerto 3001");
});