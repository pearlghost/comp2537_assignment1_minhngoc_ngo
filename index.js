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
const { title } = require("process");

const app = express();
app.set("view engine", "ejs");

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
const ObjectId = require("mongodb").ObjectId;

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

// Admin Page
app.get("/admin", async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }

  if (req.session.user_type !== "admin") {
    return res.status(403).render("error", {
      title: "403 - Forbidden",
      message: "Not Authorized",
      backLink: "/",
    });
  }

  const users = await userCollection.find().toArray();

  res.render("admin", {
    title: "Admin Dashboard",
    user: req.session.user,
    user_type: req.session.user_type,
    users: users,
  });
});

// Home Page
app.get("/", (req, res) => {
  res.render("index", {
    user: req.session.user,
    user_type: req.session.user_type,
    title: "Home",
  });
});

// Sign Up Page
app.get("/signup", (req, res) => {
  res.render("signup", {
    user: req.session.user,
    user_type: req.session.user_type,
    title: "Sign Up",
  });
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
    if (await userCollection.findOne({ email: email.trim() })) {
      errorMessage = "User already exists";
    }

    return res.render("error", {
      title: "Error",
      message: errorMessage,
      backLink: "/signup",
      user: req.session.user,
      user_type: req.session.user_type,
    });
  }

  const hashedPassword = await bcrypt.hash(password.trim(), 10);

  await userCollection.insertOne({
    username: username.trim(),
    email: email.trim(),
    password: hashedPassword,
    user_type: "user",
  });

  req.session.user = username;
  req.session.user_type = "user";
  res.redirect("/members");
});

// Log In Page
app.get("/login", (req, res) => {
  res.render("login", {
    title: "Log In",
    user: req.session.user,
    user_type: req.session.user_type,
  });
});

// Log In Handler
app.post("/login", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const user = await userCollection.findOne({
    email: email.trim().toLowerCase(),
  });

  if (!user) {
    return res.render("error", {
      title: "Error",
      message: "User not found",
      backLink: "/login",
    });
  }

  const valid = await bcrypt.compare(password.trim(), user.password);

  if (!valid) {
    return res.render("error", {
      title: "Error",
      message: "Invalid Password",
      backLink: "/login",
    });
  }

  req.session.user = user.username;
  req.session.user_type = user.user_type;
  res.redirect("/members");
});

// Promote User Handler
app.get("/promote/:id", async (req, res) => {
  if (req.session.user_type !== "admin") {
    return res.status(403).send("Not Authorized");
  }

  await userCollection.updateOne(
    { _id: new ObjectId(req.params.id) },
    {
      $set: {
        user_type: "admin",
      },
    },
  );

  res.redirect("/admin");
});

// Demote User Handler
app.get("/demote/:id", async (req, res) => {
  if (req.session.user_type !== "admin") {
    return res.status(403).send("Not Authorized");
  }

  await userCollection.updateOne(
    { _id: new ObjectId(req.params.id) },
    {
      $set: {
        user_type: "user",
      },
    },
  );

  res.redirect("/admin");
});

// Members Page
app.get("/members", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  const imagesPath = path.join(__dirname, "public/img");

  const images = fs.readdirSync(imagesPath).filter((file) => {
    return (
      file.endsWith(".png") || file.endsWith(".jpg") || file.endsWith(".jpeg")
    );
  });

  res.render("members", {
    title: "Members Area",
    user: req.session.user,
    user_type: req.session.user_type,
    images: images,
  });
});

// Logout Page
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// 'Try-catch' 404 page not found Page
app.use((req, res) => {
  res.status(404).render("404", {
    title: "404 - Not Found",
    user: req.session.user,
    user_type: req.session.user_type,
  });
});

app.listen(port, () => {
  console.log("Server running in http://localhost:" + port);
});
