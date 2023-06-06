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
    const userData = req.body;
    const enteredEmail = userData.email;
    const enteredConfirmEmail = userData['confirm-email'] // 대쉬(-)가 들어가있을 경우, 대체 표기법 사용
    const enteredPassword = userData.password;

    const user = {
        email: enteredEmail,
        password: enteredPassword,
    };

    await db.getDb().collection('users').insertOne(user);

    res.redirect('/login');
})
```

    -   비밀번호 해싱 (보완)
        -   일반텍스트로 저장되는 문제
            -   해킹, 데이터 손상, 손실, 동일비밀번호 사용
        -   해싱 알고리즘을 통한 비밀번호 변경
        -   타사패키지 사용 (bcryptjs)
            -   npm bcryptjs
            -   bcrypt.hash(password, strongness)
            -   원래 암호로 다시 변환할 수 없는 해시 생성

```JavaScript
const bcrypt = require('bcryptjs');

router.post('/signup', async function (req, res){
    const userData = req.body;
    const enteredEmail = userData.email;
    const enteredConfirmEmail = userData['confirm-email'] // 대쉬(-)가 들어가있을 경우, 대체 표기법 사용
    const enteredPassword = userData.password;

    const hashedPassword = await bcrypt.hash(enteredPassword, 12);

    const user = {
        email: enteredEmail,
        password: hashedPassword,
    };

    await db.getDb().collection('users').insertOne(user);

    res.redirect('/login');
})
```

## 2) 로그인 기능

    -   라우트 작업

```JavaScript
router.post('/login', async function (req, res) {
    const userData = req.body;
    const enteredEmail = userData.email;
    const enteredPassword = userData.password;

    const existingUser = await db.getDb().collection('users').findOne({ email: enteredEmail})

    if (!existingUser){
        consol.log('Could not log in!');
        return res.redirect('/login');
    }

    const passwordAreEqual = await bcrypt.compare(enteredPassword, existingUser.password);

    if(!passwordAreEqual){
        consol.log('Could not log in - passwaords are not equal!');
        return res.rediret('/login');
    }
    
    console.log('User is authenticated!');
    res.redirect('/admin');
})

```
