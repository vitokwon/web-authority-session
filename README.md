# 사용자 인증과 세션과 쿠키

- 사용자 가입, 프로필 생성, 자격 증명, 로그
- 인증이란 무엇인가?
  - 모든 사람이 엑세스할 수 없어야 하는 특정한 영역에 접근 권한 부여
    - 개인 프로필
    - 장바구니, 주문기록
    - 관리자 페이지
- 인증 구현의 3 단계
  - 계정 생성
  - 로그인
  - 권한 부여

## 1) 기본 가입 기능

    -   라우트 작업

```JavaScript
router.post('/signup', async function (req, res){
    const userData = req.body; // 클라이언트 입력값 저장
    const enteredEmail = userData.email; // 입력값에서 이메일 추출
    const enteredConfirmEmail = userData['confirm-email'] // 대쉬(-)가 들어가있을 경우, 대체 표기법 사용
    const enteredPassword = userData.password; // 입력값에서 패스워드 추출

    const user = { // 유저 객체로 이메일,패스워드 저장
        email: enteredEmail,
        password: enteredPassword,
    };

    await db.getDb().collection('users').insertOne(user); // 생성한 유저 객체 삽입

    res.redirect('/login');
})
```

    -   비밀번호 해싱 (보완)
        -   일반텍스트로 저장되는 문제
            -   해킹, 데이터 손상, 손실, 동일비밀번호 사용`
        -   해싱 알고리즘을 통한 비밀번호 변경
        -   타사패키지 사용 (bcryptjs)
            -   npm install bcryptjs
            -   bcrypt.hash(password, strongness)
            -   원래 암호로 다시 변환할 수 없는 해시 생성

```JavaScript
const bcrypt = require('bcryptjs');

router.post('/signup', async function (req, res){
    const userData = req.body; // 클라이언트 입력값 저장
    const enteredEmail = userData.email; // 저장된 입력값에서 이메일 추출
    const enteredConfirmEmail = userData['confirm-email'] // 대쉬(-)가 들어가있을 경우, 대체 표기법 사용
    const enteredPassword = userData.password; // 저장된 입력값에서 패스워드 추출

    // 타사 패키지 사용하여 비밀번호 해싱 (bcryptjs)
    const hashedPassword = await bcrypt.hash(enteredPassword, 12); // 추출한 패스워드 해싱

    const user = { //유저 객체 생성 후 이메일,패스워드 저장
        email: enteredEmail,
        password: hashedPassword, //해싱값 저장
    };

    await db.getDb().collection('users').insertOne(user); // 생성한 유저 객체 삽입

    res.redirect('/login');
})
```

## 2) 로그인 기능

    -   라우트 작업

```JavaScript
router.post('/login', async function (req, res) {

    // 사용자 입력값 저장 및 추출
    const userData = req.body;
    const enteredEmail = userData.email;
    const enteredPassword = userData.password;

    // 가입된 내역 확인
    const existingUser = await db.getDb().collection('users').findOne({ email: enteredEmail})

    // 미존재 시, login 페이지로 리다이렉트
    if (!existingUser){
        consol.log('Could not log in!');
        return res.redirect('/login');
    }

    // 비밀번호 일치 확인
    const passwordAreEqual = await bcrypt.compare(enteredPassword, existingUser.password);

    // 비밀번호 미일치 시, login 페이지로 리다이렉트
    if(!passwordAreEqual){
        consol.log('Could not log in - passwaords are not equal!');
        return res.rediret('/login');
    }

    // 로그인 성공
    console.log('User is authenticated!');
    res.redirect('/admin');
})

```

## 3) 회원 가입 시, 입력된 정보의 유효성 검사

    -   빈 이메일 주소 방지
    -   중복 이메일 주소 방지방지

```JavaScript
router.post('/signup', async function (req, res){
    // 사용자 입력값 저장 및 추출
    const userData = req.body;
    const enteredEmail = userData.email;
    const enteredConfirmEmail = userData['confirm-email'] // 속성에 대쉬(-)가 들어가있을 경우, 대체 표기법 사용
    const enteredPassword = userData.password;

    //  입력된 이메일값의 유효성 검사
    if(!enteredEmail
    || !enteredConfirmEmail
    || enteredPassword
    || enteredPassword.trim() < 6
    || enteredEmail !== enteredConfirmEmail
    || !enteredEmail.incldues('@')
    ){
        console.log('Incorrect data');
        return res.redirect('/signup');
    }

    // 가입 내역 확인
    const existingUser = await db.getDb().collection('users').findOne({ email: enteredEmail});

    // 가입 내역 있을 시, redirect
    if (existingUser) {
        console.log('User exists already')
        return res.redirect('/signup');
    }

    //  비밀번호 해싱
    const hashedPassword = await bcrypt.hash(enteredPassword, 12);

    //  유저 객체 생성 후, 입력값 저장
    const user = {
        email: enteredEmail,
        password: hashedPassword,
    };

    // 유저 객체 삽입
    await db.getDb().collection('users').insertOne(user);

    res.redirect('/login');
})
```

## 4) 세션 & 쿠키

    -   일종의 티켓팅 시스템
        -   로그인과 함께 티켓 생성 후 데이터베이스에 저장
        -   티켓 확인 후 엑세스 권한 부여
        -   권한이 없을 시, 401 에러 페이지 랜더링

    -   세션과 쿠키
        -   인증 전용이 아님, 모든 사용자가 세션(다양한 데이터)을 수신
        -   쿠키는 클라이언트, 세션은 서버
        -   서버에서 생성하는 고유한 ID가 포함된 티켓 (모든 방문자는 각자의 세션 소유)
            1.  (클라이언트)    :    로그인 자격 증명
            2.  (서버)  :   로그인 자격 증명 검증
            3.  (서버)  :   티켓(세션 with Unique ID) 생성 후 데이터베이스에 저장
            4.  (서버)  :   세션 ID가 포함된 `쿠키`를 사용자에게 보냄
            5.  (클라이언트)    :   자동으로 `쿠키`를 저장하고 관리
            6.  세션과 쿠키 검증을 통한 권한 부여

```JavaScript
router.get('/admin', function (req, res ){
    // Check the user "ticket"
    res.render('admin');
})
```

## 5) 웹사이트에 세션 지원 추가

    -   세션과 쿠키가 인증 목적 외에 자주 사용될 수 있음을 염두
    -   타사 패키지 사용
        -   세션의 경우 : express-session
        -   쿠키의 경우 : cookie-parser
            *** express-session에서 자동으로 세션 쿠키 관리해주므로 cookie-parser 설치 불필요
        -   npm install express-session
    -   세션 기능 설정 필요 (미들웨어 구현)
    -   세션 저장 위치 설정
        -   express-session 공식 문서에서 DB별 사용법 확인
        -   npm connect-mongodb-session

```JavaScript
const session = require('express-session');
const mongodbStore = require('connect-mongodb-session');

const MongoDBStore = mongodbStore(session);

const sessionStore = new MongoDBStore({
    uri: 'mongodb://localhost:27017',
    databaseName: 'auth-demo'
    collection: 'sessions'
})

app.use(session({
    secret: 'super-secret';,
    resave: false, // 세션 데이터가 변경됐을 때만 데이터베이스에 다시 저장, true면 무조건 재저장
    saveUninitialized: false, // 비활성 세션들은 저장하지 않음
    store: sessionStore
    //  저장 위치 (1. 메모리(휘발성,많은 트래픽), 2. 데이터베이스 저장)
    //  express-session의 공식문서에서 호환가능한 스토리지와 사용방법을 확인할 수 있음.
    //  npm connect-mongodb-session

}));
```

## 6) 세션에 인증 데이터 추가

    -   로그인한 경우 세션에 새 데이터 추가 (플래그 정보)

```JavaScript
router.post('/login', async function (req, res) {

    // 사용자 입력값 저장 및 추출
    const userData = req.body;
    const enteredEmail = userData.email;
    const enteredPassword = userData.password;

    // 가입된 내역 확인
    const existingUser = await db.getDb().collection('users').findOne({ email: enteredEmail})

    // 미존재 시, login 페이지로 리다이렉트
    if (!existingUser){
        consol.log('Could not log in!');
        return res.redirect('/login');
    }

    // 비밀번호 일치 확인
    const passwordAreEqual = await bcrypt.compare(enteredPassword, existingUser.password);

    // 비밀번호 미일치 시, login 페이지로 리다이렉트
    if(!passwordAreEqual){
        consol.log('Could not log in - passwaords are not equal!');
        return res.rediret('/login');
    }

    // 로그인 성공 후, 세션에 새 데이터 추가
    // console.log('User is authenticated!');
    req.session.user = { id: existingUser._id, email: existingUser_id.email };
    req.session.isAuthenticated = true;

    // 'express-session'을 통해 세션이 자동으로 DB에 저장될 것임.
    //  DB 저장보다 'redirect'가 더 빨리 작동될 수 있음 (race 컨디션)
    //  'session.save'의 콜백함수로 정장이 완료되면 redirect 호출
    req.session.save(function() {
      res.redirect('/admin');
    })
})

```

## 7) 세션과 쿠키를 통한 엑세스 제어

    -   세션 생성 후, 모든 요청과 함께 자동으로 브라우저로 쿠키가 전송 됨.

```JavaScript
    rotuer.get('/admin', function(req,res){
        // 세션 내부 정보 확인
        if (!req.session.isAuthenticated) {
            return res.status(401).render('401') // 상태 코드와 401에러페이지 랜더링
        }
    })
```

    -   기간 만료 설정
    -   대부분 브라우저가 기본값으로 종료 시, 세션 만료시킴

```JavaScript
app.use(session({
    secret: 'super-secret';,
    resave: false, // 세션 데이터가 변경됐을 때만 데이터베이스에 다시 저장, true면 무조건 재저장
    saveUninitialized: false, // 비활성 세션들은 저장하지 않음

    //  저장 위치 (1. 메모리(휘발성,많은 트래픽), 2. 데이터베이스 저장)
    //  express-session의 공식문서에서 호환가능한 스토리지와 사용방법을 확인할 수 있음.
    //  npm connect-mongodb-session
    store: sessionStore

    // 만료 설정, 밀리초 단위
    cookie: {
        maxAge: 60 * 1000 // 1분
        maxAge: 60 * 60 * 1000 // 1시간
        maxAge: 24 * 60 * 60 * 1000 // 1일
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30일
    }
}));
```

## 8) 로그아웃 기능

    -   세션에서 인증 데이터 삭제
    -   세션은 많은 데이터를 갖고 있을 수 있으므로 세션 자체를 삭제하면 안됨
    -   필요한 데이터만 삭제

```JavaScript
router.post("/logout", function (req, res) {
    req.session.user = null; // 거짓으로 처리
    req.session.usAuthenticated = false;
    res.redirect('/');
});
```

## 8) 쿠키에 대해서

    -   자동 생성된 쿠키는 클라이언트로 다시 전송되어 브라우저에 저장 됨
    -   개발도구 - 애플리케이션 - 쿠키에서 확인 가능
    -   로그인 시, '개발도구-네트워크-로그인-헤더'에서 쿠키 자동 설정(Set-Cookie') 됨. (express-session)
        -   세션과 관련되지 않은 다른 쿠키 관리를 하려면 cookie-parser 패키지 사용. (nodeJS)
    -   다음 행동('admin') 응답에서는 Set-Cookie가 아니라 Cookie가 있음
        -   URL에 속하는 모든 요청에 쿠키를 전송함. (login에서 admin으로 전송)
        -   세션ID는 express-session에 의해 자동 추출

## 9) 세션에 대해서

    -   잘못된 입력을 제출했을 때, 기존 값 유지
    -   기존 입력값을 세션에 저장

```JavaScript
router.post("/signup", async function (req, res) {
  const userData = req.body;
  const enteredEmail = userData.email;
  const enteredConfirmEmail = userData["confirm-email"];
  const enteredPassword = userData.password;

  if (
    !enteredEmail ||
    !enteredConfirmEmail ||
    enteredPassword ||
    enteredPassword.trim() < 6 ||
    enteredEmail !== enteredConfirmEmail ||
    !enteredEmail.incldues("@")
  ) {

    //  잘못된 값 제출 되었을 때, 기존 값 유지시키기
    //  세션에 기존 입력값 저장
    req.session.inputData ={
        hasError: true,
        message: 'Invalid input - please check your data.'
        email: enteredEmail,
        confirmEmail: enteredConfirmEmail,
        password: enteredPassword,
    }

    //  DB저장 후, 콜백함수로 리다이렉트 실행
    req.session.save(function() {
        return res.redirect("/signup");
    })

  }

```

    -   get라우트 수정

```JavaScript
router.get("/signup", function (req, res) {
    let sessionInputData = req.session.inputData;

    // 처음 방문했을 때 inputData 초기화
    if(!sessionInputData){
        sessionInputData = {
            hasError: false,
            email: '',
            confirmEmail: '',
            password: ''
        };
    }

  res.render("signup", { inputData: sessionInputData});
});
```

    -   ejs 적용하여 보낸 값 랜더링

```html
    <h1>Signup</h1>
    <% if (inputData.hasErrr){ %>
        <p id="input-error"><%= inputData.message %>
    <% } %>
    <form action="/signup" method="POST">
      <div class="form-control">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" value="<%= inputData.email %>" required>
      </div>
      <div class="form-control">
        <label for="confirm-email">Confirm Email</label>
        <input type="email" id="confirm-email" name="confirm-email" value="<%= inputData.confrimEmail %>" required>
      </div>
      <div class="form-control">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" value="<%= inputData.password %>" required>
      </div>
      <button class="btn">Create user</button>
    </form>
    <div id="auth-alternative">
      <a class="btn btn-alt" href="/login">Login instead</a>
    </div>
  </main>
```

    -   서버크래쉬 해결

```JavaScript
    //  DB저장 후, 콜백함수로 리다이렉트 실행
    req.session.save(function() {
        return res.redirect("/signup");
    })
    return;

    // 함수 안의 return은 함수 안의 다른 코드가 실행되는 것을 막음
    // 함수 밖에 return을 추가함으로써 다른 코드 실행 방지함
```

    -   회원가입 성공 후, 세션 데이터 삭제

```JavaScript
router.get("/signup", function (req, res) {
    let sessionInputData = req.session.inputData;

    // 처음 방문했을 때 inputData 초기화
    if(!sessionInputData){
        sessionInputData = {
            hasError: false,
            email: '',
            confirmEmail: '',
            password: ''
        };
    }

    //  세션값을 변수에 저장했으므로 세션 초기화
    req.session.inputData = null;

  res.render("signup", { inputData: sessionInputData});
});
```

## 10) 권한 부여와 인증

    -   Authentication (인증)
        -   자격 증명을 사용하여 가입 및 로그인 (with credentials)
        -   제한된 리소스 및 페이지에 관한 엑세스 권한을 사용자에게 부여하기 위해 세션에 데이터를 저장
    -   Authorization (부여)
        -   사용자가 인증된 경우에도 방문할 수 있는 페이지 또는 수행할 작업을 제한
            -   각자의 주문 목록만 볼 수 있음
            -   삭제, 편집, 작성에 대한 제한

    -   권한 부여 실습
        -   더미페이지 'profile.ejs' 생성
        -   라우트 설정

```JavaScript
router.get("/profile", function (req, res) {
  if (!req.session.isAuthenticated) {
    // if(!req.session.user)
    return res.status(401).render("401");
  }
  res.render("profile");
});
```

    -   DB 데이터 수정 (플래그 추가)

```sql
db.users.updateOne({_id: ObjectId("...")}, {$set: { isAdmin: true }})
```

    -   로그인 시, 세션에 권한 값 추가

```JavaScript
  req.session.user = { id: existingUser._id, email: existingUser.email, isAdmin : existingUser.isAdmin }; // 없으면 undefined 값
```

    -   또는, 각 라우트에 권한 인증 확인 추가

```JavaScript
    
    const user = await db.getDb().collection('users').findOne({_id: req.sessions.user.id});

    if (!user || !user.isAdmin) {
        return res.status(403).render('403')
    }

    res.render('admin')
```
