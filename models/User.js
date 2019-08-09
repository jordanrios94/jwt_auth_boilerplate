const bcrypt = require('bcrypt');
const uniqueValidator = require('mongoose-unique-validator');
const mongoose = require('mongoose');
const { Schema } = mongoose;
const SALT_WORK_FACTOR = 10;

const UserSchema = new Schema(
  {
    name: String,
    email: {
      type: String,
      required: true,
      index: {
        unique: true
      }
    },
    password: {
      type: String,
      required: true
    }
  },
  { timestamps: true }
);

UserSchema.pre('save', function(next) {
  const user = this;

  // only hash the password if it has been modified (or is new)
  if (!user.isModified('password')) {
    return next();
  }

  // generate a salt
  bcrypt.genSalt(SALT_WORK_FACTOR, (error, salt) => {
    if (error) {
      return next(error);
    }

    // hash the password along with our new salt
    bcrypt.hash(user.password, salt, (error, hash) => {
      if (error) {
        return next(error);
      }

      // override the cleartext password with the hashed one
      user.password = hash;
      next();
    });
  });
});

UserSchema.methods.comparePassword = function(candidatePassword, done) {
  bcrypt.compare(candidatePassword, this.password, function(error, isMatch) {
    if (error) {
      return done(error);
    }

    done(null, isMatch);
  });
};

UserSchema.plugin(uniqueValidator);

mongoose.model('users', UserSchema);
