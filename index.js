require("./utils.js");
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoDBStore = require("connect-mongo");
const Joi = require("joi");
const bcrypt = require("bcrypt");
const mongoSanitize = require("express-mongo-sanitize");

const app = express();

const port = process.env.PORT || 3000;
const expiryTimeInMs = 1000 * 60 * 60 * 24; // expires afer 1 day (ms * s * min * hr)

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

var mongoStore = MongoDBStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: expiryTimeInMs },
  }),
);

app.listen(port, () => {
  console.log("Server running");
});
