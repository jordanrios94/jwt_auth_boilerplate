const mongoose = require('mongoose');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const keys = require('../config/keys');
const User = mongoose.model('users');
const EXPIRY_TIME = 604800;

module.exports = {
  async login(req, res) {
    passport.authenticate('local', { session: false }, (error, user, info) => {
      if (error || !user) {
        return res.status(400).json({
          message: info.message || 'Something is not right',
          user: user
        });
      }

      req.login(user, { session: false }, error => {
        if (error) {
          res.send(error);
        }

        // generate a signed son web token with the contents of user object and return it in the response
        const token = jwt.sign(user.toJSON(), keys.jwtSecret, {
          expiresIn: EXPIRY_TIME // 1 week
        });

        res.json({ user, token });
      });
    })(req, res);
  },
  async create(req, res) {
    try {
      // create the user
      const user = await new User({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password
      }).save();

      // generate a signed son web token with the contents of user object and return it in the response
      const token = jwt.sign(user.toJSON(), keys.jwtSecret, {
        expiresIn: EXPIRY_TIME // 1 week
      });

      res.json({ user, token });
    } catch (error) {
      res.status(400).send(error);
    }
  }
};
