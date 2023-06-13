const express = require("express");
const bcrypt = require("bcryptjs");

const db = require("../data/database");

const router = express.Router();

router.get("/", function (req, res) {
  res.render("welcome");
});

router.get("/signup", function (req, res) {
  let sessionInputData = req.session.inputData;

  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: "",
      confirmEmail: "",
      password: "",
    };
  }

  req.session.inputData = null;

  res.render("signup", { inputData: sessionInputData });
});

router.get("/login", function (req, res) {
  let sessionInputData = req.session.inputData;
  // 첫방문 시, inputData 초기화 (입력창 빈칸유지)
  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: "",
      password: "",
    };
  }
  // 세션(inputData) 초기화
  req.session.inputData = null;
  //  로그인 성공 후, 저장된 세션값 전달
  res.render("login", { inputData: sessionInputData });
});

router.post("/signup", async function (req, res) {
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredConfirmEmail = userData["confirm-email"];
  const enteredPassword = userData.password;

  if (
    !enteredEmail ||
    !enteredConfirmEmail ||
    !enteredPassword ||
    enteredPassword.trim() < 6 ||
    enteredEmail !== enteredConfirmEmail ||
    !enteredEmail.includes("@")
  ) {
    // 기존 입력값 세션에 저장하여 처리 실패 후에도 입력 유지
    req.session.inputData = {
      hasError: true,
      message: "Invalid input - please check your data.",
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };

    req.session.save(function () {
      return res.redirect("/signup");
    });
    return;
  }

  // 가입 내역 확인
  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: enteredEmail });

  // 사용자 이미 존재 시,
  if (existingUser) {
    req.session.inputData = {
      hasError: true,
      message: "User exists already!",
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };

    // 세션을 저장한 후에만 리다이렉트
    req.session.save(function () {
      res.redirect("/signup");
    });
    // 사용자 가입에 실패한 경우, 코드 진행 전 반환.
    return;
  }

  const hashedPassword = await bcrypt.hash(enteredPassword, 12);

  const user = {
    email: enteredEmail,
    password: hashedPassword,
  };

  await db.getDb().collection("users").insertOne(user);

  res.redirect("/login");
});

router.post("/login", async function (req, res) {
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredPassword = userData.password;

  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: enteredEmail });

  if (!existingUser) {
    // 가입된 사용자가 없을 시
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in - please check your credentials!",
      email: enteredEmail,
      password: enteredPassword,
    };
    // 세션을 저장한 후에만 리다이렉트
    req.session.save(function () {
      res.redirect("/login");
    });
    // 사용자 가입에 실패한 경우, 코드 진행 전 반환.
    return;
  }

  const passwordAreEqual = await bcrypt.compare(
    enteredPassword,
    existingUser.password
  );

  if (!passwordAreEqual) {
    // 패스워드 불일치 시
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in - please check your credentials!",
      email: enteredEmail,
      password: enteredPassword,
    };

    req.session.save(function () {
      return res.redirect("/login");
    });
    return;
  }

  req.session.user = { id: existingUser._id, email: existingUser.email };
  req.session.isAuthenticated = true;

  req.session.save(function () {
    res.redirect("/profile");
  });
});

router.get("/admin", async function (req, res) {
  // 미들웨어설정함으로써 locals 사용 가능
  if (!res.locals.isAuth) {
    // if(!req.session.isAuthenticated) {
    // if(!req.session.user)
    return res.status(401).render("401");
  }

  // 미들웨어 설정으로 사용자를 갖고 올 필요 없어짐
  // const user = await db
  //   .getDb()
  //   .collection("users")
  //   .findOne({ _id: req.session.user.id });

  // 미들웨어설정으로 locals 사용
  if (!res.locals.isAdmin) {
    // if (!user || !user.isAdmin) {
    return res.status(403).render("403"); // 다음코드가 실행되지 않도록 return 사용
  }

  res.render("admin");
});

router.get("/profile", function (req, res) {
  // 미들웨어 설정로 locals 사용
  if (!res.locals.isAuth) {
    // if (!req.session.isAuthenticated) {
    // if(!req.session.user)
    return res.status(401).render("401");
  }
  res.render("profile");
});

router.post("/logout", function (req, res) {
  req.sessionStore.user = null;
  req.session.isAuthenticated = false;
  res.redirect("/");
});

module.exports = router;
