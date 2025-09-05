var express = require('express');
var router = express.Router();
var bcrypt = require('bcrypt');
var saltRounds = 10;
const { ObjectId } = require('mongodb');
const e = require('express');

var SignUpType = {
  Existing_username: 0,
  Existing_nickname: 1,
  Success: 2,
}

var ResponseType = {
  Invalid_username: 0,
  Invalid_password: 1,
  Success: 2,
}

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.post('/signup', async function(req, res, next) {
  try{
    var username = req.body.username;
    var password = req.body.password;
    var nickname = req.body.nickname;

    if (!username || !password || !nickname) {
      return res.status(400).json({ message: 'All fields are required.'});
    }

    var database = req.app.get('database');
    var users = database.collection('users');

    var existingUser = await users.findOne({
      $or: [{ username: username }, { nickname: nickname }]
    });

    if (existingUser) {
      if (existingUser.username === username) {
        return res.status(409).json({ result: SignUpType.Existing_username });
      }
      if (existingUser.nickname === nickname) {
        return res.status(409).json({ result: SignUpType.Existing_nickname });
      }
    }

    var salt = bcrypt.genSaltSync(saltRounds);
    var hash = bcrypt.hashSync(password, salt);

    await users.insertOne({
      username : username,
      password: hash,
      nickname: nickname,
      createdAt: new Date()
    });

    res.status(201).json({ result : SignUpType.Success });
  } catch (error) {
    console.error('Error during signup:', error);
    res.status(500).json({ message: 'Internal server error.' });
}});

router.post('/signin', async function(req, res, next) {
  try {
    var username = req.body.username;
    var password = req.body.password;

    if (!username || !password) {
      return res.status(400).json({ message: 'All fields are required.'});
    }

    var database = req.app.get('database');
    var users = database.collection('users');

    const existingUser = await users.findOne({ username: username});
    if (existingUser) {
      var compareResult = bcrypt.compareSync(password, existingUser.password);
      if (compareResult) {
        req.session.isAuthenticated = true;
        req.session.userId = existingUser._id.toString();
        req.session.username = existingUser.username;
        req.session.nickname = existingUser.nickname;
        res.json({ result : ResponseType.Success });
      } else {
        res.status(401).json({ result : ResponseType.Invalid_password });
      }
    } else {
      res.status(401).json({ result : ResponseType.Invalid_username });
    }
  } catch(error) {
    console.error('Error during signup:', error);
    res.status(500).json({ message: 'Internal server error.' });
}});

module.exports = router;
