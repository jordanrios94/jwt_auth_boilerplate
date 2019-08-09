const keys = require('../config/keys');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const passportJWT = require('passport-jwt');
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;
const User = mongoose.model('users');

passport.use(
  new LocalStrategy(
    {
      usernameField: 'email',
      passwordField: 'password'
    },
    function(email, password, done) {
      User.findOne({ email }, function(error, user) {
        if (error) {
          return done(error);
        }

        if (!user) {
          return done(null, false, { message: 'Incorrect email or password.' });
        }

        user.comparePassword(password, function(error, isMatch) {
          if (error) {
            return done(null, false, {
              message: 'Incorrect email or password.'
            });
          }

          if (!isMatch) {
            return done(null, false, {
              message: 'Incorrect email or password.'
            });
          }

          return done(null, user, { message: 'Logged In Successfully' });
        });
      });
    }
  )
);

passport.use(
  new JWTStrategy(
    {
      jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
      secretOrKey: keys.jwtSecret
    },
    function(jwtPayload, done) {
      // find the user in db if needed. This functionality may be omitted if you store everything you'll need in JWT payload.
      User.findById(jwtPayload._id)
        .then(user => {
          return done(null, user);
        })
        .catch(error => {
          return done(error, null);
        });
    }
  )
);
