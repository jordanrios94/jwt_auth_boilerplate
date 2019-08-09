const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const bodyParser = require('body-parser');
const keys = require('./config/keys');

require('./models/User');
require('./services/passport');

mongoose.connect(keys.mongoURI, { useNewUrlParser: true });

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());

const auth = require('./routes/auth');
const user = require('./routes/user');

app.use('/auth', auth);
app.use('/api/user', passport.authenticate('jwt', { session: false }), user);

const PORT = process.env.PORT || 5000;
app.listen(PORT);
