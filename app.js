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

// 노출될 데이터를 설정하는 미들웨어 설정
app.use(async function (req, res, next) {
  const user = req.session.user;
  const isAuth = req.session.isAuthenticated;

  // false, 0, "", null, undefined, NaN = falsy 값
  if (!user || !isAuth) {
    return next(); // 다음 미들웨어, 또는 라우트로 이동시킴
  }

  const userDoc = await db
    .getDb()
    .collection("users")
    .findOne({ _id: user.id });
  const isAdmin = userDoc.isAdmin;

  // 수집한 정보를 특정 위치에 저장하기 위한 expressJS 기능
  // 데이터를 명시적으로 저장하지 않고 모든 템플릿에서 엑세스 가능
  // 해당 요청의 응답동안만 사용 가능함. (새 요청에서는 데이터 없음)
  // 전역 변수임.
  res.locals.isAuth = isAuth;
  res.locals.isAdmin = isAdmin;

  // demoRoutes에 도달하기 전 모든 요청에 대해 실행되므로 굉장히 유용함
  // 이제 header.ejs에서 사용 가능함. (각 라우트별로 변수로 보내줄 필요 없어졌음)
  next();
});

app.use(demoRoutes);

app.use(function (error, req, res, next) {
  console.log(error);
  res.render("500");
});

db.connectToDatabase().then(function () {
  app.listen(3000);
});
