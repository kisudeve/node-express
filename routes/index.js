// routes/index.js
var express = require("express");
var jwt = require("jsonwebtoken");

var router = express.Router();

// =========================
// 메모리 기반 저장소 (DB 대신)
// =========================
const users = [
  {
    id: "user-1",
    email: "test@example.com",
    password: "qwe123!!",
    name: "테스트 유저",
  },
];

let postIdSeq = 1;
const posts = [];

// =========================
// JWT 설정
// =========================
const ACCESS_TOKEN_SECRET = "access-secret";
const REFRESH_TOKEN_SECRET = "refresh-secret";

const ACCESS_TOKEN_EXPIRES_IN = "5s";
const REFRESH_TOKEN_EXPIRES_IN = "10s";

function signAccessToken(userId) {
  return jwt.sign({ sub: userId }, ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRES_IN,
  });
}

function signRefreshToken(userId) {
  return jwt.sign({ sub: userId }, REFRESH_TOKEN_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRES_IN,
  });
}

function setAuthCookies(res, userId) {
  const accessToken = signAccessToken(userId);
  const refreshToken = signRefreshToken(userId);

  res.cookie("access_token", accessToken, {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
    path: "/",
  });

  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
    path: "/",
  });
}

// =========================
// 미들웨어
// =========================
function authMiddleware(req, res, next) {
  const accessToken = req.cookies?.access_token;
  const refreshToken = req.cookies?.refresh_token;

  if (!accessToken && !refreshToken) {
    return res.status(401).json({ message: "No token" });
  }

  if (accessToken) {
    try {
      const payload = jwt.verify(accessToken, ACCESS_TOKEN_SECRET);
      req.user = { id: payload.sub };
      return next();
    } catch (e) {
      if (e.name !== "TokenExpiredError") {
        return res.status(401).json({ message: "Invalid token" });
      }
    }
  }

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token" });
  }

  try {
    const refreshPayload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    const userId = refreshPayload.sub;

    const user = users.find((u) => u.id === userId);
    if (!user) {
      res.clearCookie("access_token", { path: "/" });
      res.clearCookie("refresh_token", { path: "/" });
      return res
        .status(401)
        .json({ message: "User not found for refresh token" });
    }

    const newAccessToken = signAccessToken(userId);
    res.cookie("access_token", newAccessToken, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      path: "/",
    });

    req.user = { id: userId };
    return next();
  } catch (e) {
    res.clearCookie("access_token", { path: "/" });
    res.clearCookie("refresh_token", { path: "/" });
    return res.status(401).json({ message: "Invalid refresh token" });
  }
}

// =========================
// Routes
// =========================

/* GET home page. */
router.get("/", function (req, res, next) {
  // 기존 템플릿 렌더링을 쓰고 싶으면:
  // return res.render('index');

  // 지금은 API처럼 응답:
  return res.json("Hello, World");
});

// 회원가입
router.post("/auth/signup", function (req, res) {
  const { email, password, name } = req.body || {};

  if (!email || !password || !name) {
    return res
      .status(400)
      .json({ message: "email, password, name 모두 필요합니다." });
  }

  const existing = users.find((u) => u.email === email);
  if (existing) {
    return res.status(409).json({ message: "이미 존재하는 이메일입니다." });
  }

  const newUser = {
    id: `user-${users.length + 1}`,
    email,
    password,
    name,
  };

  users.push(newUser);
  setAuthCookies(res, newUser.id);

  return res.status(201).json({
    ok: true,
    user: { id: newUser.id, email: newUser.email, name: newUser.name },
  });
});

// 로그인
router.post("/auth/login", function (req, res) {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ message: "email과 password가 필요합니다." });
  }

  const user = users.find((u) => u.email === email);
  if (!user || user.password !== password) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  setAuthCookies(res, user.id);
  return res.json({ ok: true });
});

// 현재 로그인 유저
router.get("/me", authMiddleware, function (req, res) {
  const user = users.find((u) => u.id === req.user?.id);
  if (!user) return res.status(404).json({ message: "User not found" });

  return res.json({ id: user.id, email: user.email, name: user.name });
});

// 로그아웃
router.post("/auth/logout", function (req, res) {
  res.clearCookie("access_token", { path: "/" });
  res.clearCookie("refresh_token", { path: "/" });
  return res.json({ ok: true });
});

// 글 작성
router.post("/posts", authMiddleware, function (req, res) {
  const { title, content } = req.body || {};
  if (!title || !content) {
    return res.status(400).json({ message: "title과 content는 필수입니다." });
  }

  const newPost = {
    id: postIdSeq++,
    title,
    content,
    authorId: req.user.id,
    createdAt: new Date().toISOString(),
  };

  posts.unshift(newPost);
  return res.status(201).json({ ok: true, post: newPost });
});

// 글 목록
router.get("/posts", function (req, res) {
  const postSummaries = posts.map((post) => {
    const author = users.find((u) => u.id === post.authorId);
    return {
      id: post.id,
      title: post.title,
      preview:
        post.content.length > 60
          ? post.content.slice(0, 60) + "..."
          : post.content,
      authorName: author?.name || "알 수 없음",
      createdAt: post.createdAt,
    };
  });

  return res.json(postSummaries);
});

module.exports = router;
