// app.js
const express = require('express')
const sqlite3 = require('sqlite3')
const {open} = require('sqlite')
const path = require('path')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const dbPath = path.join(__dirname, 'twitterClone.db')
const app = express()

app.use(express.json())

let db = null

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () =>
      console.log('Server running at http://localhost:3000/'),
    )
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    process.exit(1)
  }
}

initializeDbAndServer()

// Authentication Middleware
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers['authorization']
  let jwtToken
  if (authHeader !== undefined) {
    const parts = authHeader.split(' ')
    jwtToken = parts[1]
  }
  if (jwtToken === undefined) {
    response.status(401).send('Invalid JWT Token')
    return
  }
  jwt.verify(jwtToken, 'MY_SECRET_KEY', (error, payload) => {
    if (error) {
      response.status(401).send('Invalid JWT Token')
    } else {
      request.username = payload.username
      request.userId = payload.userId
      next()
    }
  })
}

// API 1: Register
app.post('/register/', async (request, response) => {
  const {username, password, name, gender} = request.body
  const userCheckQuery = `SELECT * FROM user WHERE username = $username`
  const dbUser = await db.get(userCheckQuery, {$username: username})

  if (dbUser !== undefined) {
    response.status(400).send('User already exists')
    return
  }

  if (password.length < 6) {
    response.status(400).send('Password is too short')
    return
  }

  const hashedPassword = await bcrypt.hash(password, 10)
  const createUserQuery = `
    INSERT INTO user (name, username, password, gender)
    VALUES ($name, $username, $password, $gender)`
  await db.run(createUserQuery, {
    $name: name,
    $username: username,
    $password: hashedPassword,
    $gender: gender,
  })
  response.send('User created successfully')
})

// API 2: Login
app.post('/login/', async (request, response) => {
  const {username, password} = request.body
  const userQuery = `SELECT * FROM user WHERE username = $username`
  const dbUser = await db.get(userQuery, {$username: username})

  if (dbUser === undefined) {
    response.status(400).send('Invalid user')
    return
  }

  const isPasswordCorrect = await bcrypt.compare(password, dbUser.password)
  if (isPasswordCorrect) {
    const payload = {username: username, userId: dbUser.user_id}
    const jwtToken = jwt.sign(payload, 'MY_SECRET_KEY')
    response.send({jwtToken})
  } else {
    response.status(400).send('Invalid password')
  }
})

// Helper: Check if following
const isFollowingUser = async (request, tweetId) => {
  const userId = request.userId
  const query = `
    SELECT tweet.tweet_id AS tid
    FROM tweet
    INNER JOIN follower ON tweet.user_id = follower.following_user_id
    WHERE tweet.tweet_id = $tweetId AND follower.follower_user_id = $userId`
  const result = await db.get(query, {$tweetId: tweetId, $userId: userId})
  return result !== undefined
}

// API 3: Latest feed
app.get('/user/tweets/feed/', authenticateToken, async (request, response) => {
  const userId = request.userId
  const query = `
    SELECT u.username AS username, t.tweet AS tweet, t.date_time AS dateTime
    FROM follower f
    INNER JOIN tweet t ON f.following_user_id = t.user_id
    INNER JOIN user u ON u.user_id = t.user_id
    WHERE f.follower_user_id = $userId
    ORDER BY t.date_time DESC
    LIMIT 4`
  const tweets = await db.all(query, {$userId: userId})
  response.send(tweets)
})

// API 4: Following list
app.get('/user/following/', authenticateToken, async (request, response) => {
  const userId = request.userId
  const query = `
    SELECT u.name AS name
    FROM follower f
    INNER JOIN user u ON u.user_id = f.following_user_id
    WHERE f.follower_user_id = $userId`
  const following = await db.all(query, {$userId: userId})
  response.send(following)
})

// API 5: Followers list
app.get('/user/followers/', authenticateToken, async (request, response) => {
  const userId = request.userId
  const query = `
    SELECT u.name AS name
    FROM follower f
    INNER JOIN user u ON u.user_id = f.follower_user_id
    WHERE f.following_user_id = $userId`
  const followers = await db.all(query, {$userId: userId})
  response.send(followers)
})

// API 6: Tweet details
app.get('/tweets/:tweetId/', authenticateToken, async (request, response) => {
  const tweetId = request.params.tweetId
  const canAccess = await isFollowingUser(request, tweetId)

  if (!canAccess) {
    response.status(401).send('Invalid Request')
    return
  }

  const query = `
    SELECT t.tweet AS tweet,
      COALESCE(likes_count.likes, 0) AS likes,
      COALESCE(replies_count.replies, 0) AS replies,
      t.date_time AS dateTime
    FROM tweet t
    LEFT JOIN (
      SELECT tweet_id, COUNT(like_id) AS likes
      FROM like
      WHERE tweet_id = $tweetId
      GROUP BY tweet_id
    ) AS likes_count ON likes_count.tweet_id = t.tweet_id
    LEFT JOIN (
      SELECT tweet_id, COUNT(reply_id) AS replies
      FROM reply
      WHERE tweet_id = $tweetId
      GROUP BY tweet_id
    ) AS replies_count ON replies_count.tweet_id = t.tweet_id
    WHERE t.tweet_id = $tweetId`
  const tweetDetails = await db.get(query, {$tweetId: tweetId})
  response.send(tweetDetails)
})

// API 7: Likes list
app.get(
  '/tweets/:tweetId/likes/',
  authenticateToken,
  async (request, response) => {
    const tweetId = request.params.tweetId
    const canAccess = await isFollowingUser(request, tweetId)

    if (!canAccess) {
      response.status(401).send('Invalid Request')
      return
    }

    const query = `
    SELECT u.username AS username
    FROM like l
    INNER JOIN user u ON l.user_id = u.user_id
    WHERE l.tweet_id = $tweetId`
    const likesRows = await db.all(query, {$tweetId: tweetId})
    const likes = likesRows.map(row => row.username)
    response.send({likes})
  },
)

// API 8: Replies list
app.get(
  '/tweets/:tweetId/replies/',
  authenticateToken,
  async (request, response) => {
    const tweetId = request.params.tweetId
    const canAccess = await isFollowingUser(request, tweetId)

    if (!canAccess) {
      response.status(401).send('Invalid Request')
      return
    }

    const query = `
    SELECT u.name AS name, r.reply AS reply
    FROM reply r
    INNER JOIN user u ON r.user_id = u.user_id
    WHERE r.tweet_id = $tweetId`
    const replies = await db.all(query, {$tweetId: tweetId})
    response.send({replies})
  },
)

// API 9: User's tweets
app.get('/user/tweets/', authenticateToken, async (request, response) => {
  const userId = request.userId
  const query = `
    SELECT t.tweet AS tweet,
      COALESCE(likes_count.likes, 0) AS likes,
      COALESCE(replies_count.replies, 0) AS replies,
      t.date_time AS dateTime
    FROM tweet t
    LEFT JOIN (
      SELECT tweet_id, COUNT(like_id) AS likes
      FROM like
      GROUP BY tweet_id
    ) AS likes_count ON likes_count.tweet_id = t.tweet_id
    LEFT JOIN (
      SELECT tweet_id, COUNT(reply_id) AS replies
      FROM reply
      GROUP BY tweet_id
    ) AS replies_count ON replies_count.tweet_id = t.tweet_id
    WHERE t.user_id = $userId
    ORDER BY t.date_time DESC`
  const tweets = await db.all(query, {$userId: userId})
  response.send(tweets)
})

// API 10: Create tweet
app.post('/user/tweets/', authenticateToken, async (request, response) => {
  const tweet = request.body.tweet
  const userId = request.userId
  const dateTime = new Date().toISOString().replace('T', ' ').slice(0, 19)
  const query = `
    INSERT INTO tweet (tweet, user_id, date_time)
    VALUES ($tweet, $userId, $dateTime)`
  await db.run(query, {$tweet: tweet, $userId: userId, $dateTime: dateTime})
  response.send('Created a Tweet')
})

// API 11: Delete tweet
app.delete(
  '/tweets/:tweetId/',
  authenticateToken,
  async (request, response) => {
    const tweetId = request.params.tweetId
    const userId = request.userId

    const tweetCheckQuery = `SELECT * FROM tweet WHERE tweet_id = $tweetId AND user_id = $userId`
    const tweet = await db.get(tweetCheckQuery, {
      $tweetId: tweetId,
      $userId: userId,
    })

    if (tweet === undefined) {
      response.status(401).send('Invalid Request')
      return
    }

    await db.run(`DELETE FROM tweet WHERE tweet_id = $tweetId`, {
      $tweetId: tweetId,
    })
    response.send('Tweet Removed')
  },
)

module.exports = app
