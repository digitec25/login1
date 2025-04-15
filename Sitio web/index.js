const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt'); // Importa bcrypt para cifrar contraseñas

const app = express();
const port = 3060;

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use(express.static(__dirname)); // Sirve archivos como index.html

// Conexión a MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', // coloca tu contraseña si tienes
  database: 'bd_login_register_s7v'
});

db.connect((err) => {
  if (err) throw err;
  console.log('Conectado a la base de datos');
});

// Ruta principal (login)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Ruta del formulario de registro
app.get('/registro/Register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'registro', 'Register.html'));
});

// Ruta POST - LOGIN
app.post('/login', (req, res) => {
  const { usuario, password } = req.body;

  const query = 'SELECT * FROM usuarios WHERE usuario = ?';
  db.query(query, [usuario], (err, results) => {
    if (err) throw err;

    if (results.length > 0) {
      const user = results[0];
      
      // Compara las contraseñas utilizando bcrypt
      bcrypt.compare(password, user.password, (err, match) => {
        if (err) throw err;
        
        if (match) {
          const nombreUsuario = user.nombre || usuario;
          res.send(`
            <html>
              <head>
                <title>Login Exitoso</title>
                <style>
                  body { font-family: Arial, sans-serif; background: #0d0d0d; color: #fff1bb; text-align: center; padding: 50px; }
                  a { color: #fff; text-decoration: underline; }
                </style>
              </head>
              <body>
                <h2>✅ Usuario ingresó exitosamente</h2>
                <p>Bienvenido, <strong>${nombreUsuario}</strong></p>
                <a href="/">Volver al inicio</a>
              </body>
            </html>
          `);
        } else {
          res.send(`
            <html>
              <head>
                <title>Error de Login</title>
                <style>
                  body { font-family: Arial, sans-serif; background: #0d0d0d; color: #ff5b5b; text-align: center; padding: 50px; }
                  a { color: #fff; text-decoration: underline; }
                </style>
              </head>
              <body>
                <h2>❌ Usuario o contraseña incorrectos</h2>
                <p>Verifica tu usuario y contraseña. Si el problema persiste, es posible que el usuario no esté registrado.</p>
                <a href="/">Intentar de nuevo</a>
              </body>
            </html>
          `);
        }
      });
    } else {
      res.send(`
        <html>
          <head>
            <title>Error de Login</title>
            <style>
              body { font-family: Arial, sans-serif; background: #0d0d0d; color: #ff5b5b; text-align: center; padding: 50px; }
              a { color: #fff; text-decoration: underline; }
            </style>
          </head>
          <body>
            <h2>❌ Usuario no registrado</h2>
            <p>Por favor, regístrate primero.</p>
            <a href="/">Intentar de nuevo</a>
          </body>
        </html>
      `);
    }
  });
});

// Ruta POST - REGISTER
app.post('/register', (req, res) => {
  const { name, email, password } = req.body;

  // Verificar si el correo ya existe
  const checkQuery = 'SELECT * FROM usuarios WHERE usuario = ?';
  db.query(checkQuery, [email], (err, results) => {
    if (err) {
      console.error('Error al verificar el usuario:', err);
      res.send(`
        <html>
          <head><title>Error en el Registro</title></head>
          <body>
            <h2>❌ Hubo un error al verificar el usuario</h2>
            <p>Intenta nuevamente.</p>
            <a href="/registro/Register.html">Volver al formulario</a>
          </body>
        </html>
      `);
      return;
    }

    if (results.length > 0) {
      res.send(`
        <html>
          <head><title>Error en el Registro</title></head>
          <body>
            <h2>❌ El usuario ya está registrado</h2>
            <p>Por favor, utiliza otro correo electrónico.</p>
            <a href="/registro/Register.html">Volver al formulario</a>
          </body>
        </html>
      `);
    } else {
      // Si el usuario no existe, cifrar la contraseña y registrarlo
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          console.error('Error al cifrar la contraseña:', err);
          res.send(`
            <html>
              <head><title>Error en el Registro</title></head>
              <body>
                <h2>❌ Hubo un error al registrar al usuario</h2>
                <p>Intenta nuevamente.</p>
                <a href="/registro/Register.html">Volver al formulario</a>
              </body>
            </html>
          `);
          return;
        }

        const query = 'INSERT INTO usuarios (nombre, usuario, password) VALUES (?, ?, ?)';
        db.query(query, [name, email, hashedPassword], (err, result) => {
          if (err) {
            console.error('Error al insertar el usuario:', err);
            res.send(`
              <html>
                <head><title>Error en el Registro</title></head>
                <body>
                  <h2>❌ Hubo un error al insertar el usuario</h2>
                  <p>Intenta nuevamente.</p>
                  <a href="/registro/Register.html">Volver al formulario</a>
                </body>
              </html>
            `);
            return;
          }

          res.send(`
            <html>
              <head><title>Registro Exitoso</title></head>
              <body>
                <h2>✅ Registro exitoso</h2>
                <p>Ya puedes iniciar sesión con tus datos</p>
                <a href="/">Iniciar sesión</a>
              </body>
            </html>
          `);
        });
      });
    }
  });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});