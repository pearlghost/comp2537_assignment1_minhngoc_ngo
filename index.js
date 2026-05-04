require("./utils.js");
require("dotenv").config();

const fs = require("fs");
const path = require("path");
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const Joi = require("joi");
const bcrypt = require("bcrypt");
const mongoSanitize = require("express-mongo-sanitize");

const app = express();

const port = process.env.PORT || 3000;
const expiryTime = 60 * 60 * 1000; // expires afer 1 hour (60 mins * 60 s * 1000ms)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const { database } = include("mongoDBConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(express.json());

//Hack for express 5.x not setting req.query as writable
app.use((req, _res, next) => {
  Object.defineProperty(req, "query", {
    ...Object.getOwnPropertyDescriptor(req, "query"),
    value: req.query,
    writable: true,
  });

  next();
});

app.use(mongoSanitize({ replaceWith: "%" }));

app.use(
  session({
    secret: node_session_secret,
    store: MongoStore.create({
      mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
      collectionName: `${mongodb_session_secret}`,
    }),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: expiryTime },
  }),
);

/* Define routes */

// Home Page
app.get("/", (req, res) => {
  if (!req.session.user) {
    res.send(`
            <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                </head>
                <body>
                    <div class="container">
                        <form method="get" action="/signup">
                            <button type="submit">Sign Up</button>
                        </form>
                        <form method="get" action="/login">
                            <button type="submit">Log In</button>
                        </form>
                    </div>
                </body>
            </html>
    `);
  } else {
    res.send(`
            <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                </head>
                <body>
                    <div>
                        <h1>Welcome, ${req.session.user}!</h1>
                        <form method="get" action="/members">
                            <button type="submit">Go To Members Area</button>
                        </form>
                        <form method="get" action="/logout">
                            <button type="submit">Logout</button>
                        </form>
                    </div>
                </body>
            </html>
    `);
  }
});

// Sign Up Page
app.get("/signup", (req, res) => {
  res.send(`
            <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                </head>
                <body>
                    <div>
                        <h1>Sign Up</h1>
                        <form method="post">
                            <input name="username" type="text" placeholder="Username"/>
                            <input name="email" type="email" placeholder="Email"/>
                            <input name="password" type="password" placeholder="Password"/>
                            <button type="submit">Sign Up</button>
                        </form>
                    </div>
                </body>
            </html>
    `);
});

// Sign Up Handler
app.post("/signup", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    username: Joi.string().required(),
    email: Joi.string().required(),
    password: Joi.string().required(),
  });

  const result = schema.validate({
    username: username,
    email: email,
    password: password,
  });

  if (result.error) {
    var errorMessage = null;
    if (result.error.details[0].context.key === "username") {
      errorMessage = "Username is required";
    } else if (result.error.details[0].context.key === "email") {
      errorMessage = "Email is required";
    } else if (result.error.details[0].context.key === "password") {
      errorMessage = "Password is required";
    }

    return res.send(`
            <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                </head>
                <body>
                    <div>
                        <h1>${errorMessage}</h1>
                        <a href="/signup">Go Back</a>
                    </div>
                </body>
            </html>
    `);
  }

  if (await userCollection.findOne({ email: email.trim() })) {
    return res.send(`
            <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                </head>
                <body>
                    <div>
                        <h1>User already exists</h1>
                        <a href="/signup">Go Back</a>
                    </div>
                </body>
            </html>
    `);
  }

  const hashedPassword = await bcrypt.hash(password.trim(), 10);

  await userCollection.insertOne({
    username: username.trim(),
    email: email.trim(),
    password: hashedPassword,
  });

  req.session.user = username;
  res.redirect("/members");
});

// Log In Page
app.get("/login", (req, res) => {
  res.send(`
            <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                </head>
                <body>
                    <h1>Log In</h1>
                    <form method="post">
                        <input name="email" type="email" placeholder="Email"/>
                        <input name="password" type="password" placeholder="Password"/>
                        <button type="submit">Log In</button>
                    </form>
                </body>
            </html>
    `);
});

// Log In Handler
app.post("/login", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const user = await userCollection.findOne({
    email: email.trim().toLowerCase(),
  });

  if (!user) {
    return res.send(`
            <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                </head>
                <body>
                    <div>
                        <h1>User not found</h1>
                        <a href="/login">Go Back</a>
                    </div>
                </body>
            </html>
    `);
  }

  const valid = await bcrypt.compare(password.trim(), user.password);

  if (!valid) {
    return res.send(`
            <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                </head>
                <body>
                    <div>
                        <h1>Invalid password</h1>
                        <a href="/login">Go Back</a>
                    </div>
                </body>
            </html>
    `);
  }

  req.session.user = user.username;
  res.redirect("/members");
});

// Members Page
app.get("/members", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  const imagesPath = path.join(__dirname, "public");

  const images = fs.readdirSync(imagesPath).filter((file) => {
    return (
      file.endsWith(".png") || file.endsWith(".jpg") || file.endsWith(".jpeg")
    );
  });

  const random = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <html>
        <head>
            <link rel="stylesheet" href="/styles.css">
        </head>
        <body>
            <div style="container">
                <h1>Hello, ${req.session.user}</h1>
                <img src="/${random}" width="300" />
                <br>
                <br>
                <form method="get" action="/logout">
                    <button>Logout</button>
                </form>
            </div>
        </body>
    </html>
  `);
});

// Logout Page
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// 'Try-catch' 404 page not found Page
app.use((req, res) => {
  res.status(404).send("Page not found");
});

app.listen(port, () => {
  console.log("Server running in http://localhost:" + port);
});
