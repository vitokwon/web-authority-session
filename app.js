const path = require("path");

const express = require("express");
const session = require("express-session");

const mongodbStore = require("connect-mongodb-session");

const db = require("./data/database");
const demoRoutes = require("./routes/demo");

const MongoDBStore = mongodbStore(session);

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));

const sessionStore = new MongoDBStore({
  uri: "mongodb://localhost:27017",
  databaseName: "auth-demo",
  collection: "sessions",
});

app.use(
  session({
    secret: "user-secret",
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
  })
);

app.use(demoRoutes);

app.use(function (error, req, res, next) {
  console.log(error);
  res.render("500");
});

db.connectToDatabase().then(function () {
  app.listen(3000);
});
