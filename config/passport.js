const passport = require('passport');
import dotenv from 'dotenv';
dotenv.config();

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { client_id, client_secret } = require('./config/google-credentials.json');
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/auth/google/callback'
},
(accessToken, refreshToken, profile, done) => {
    // Here you would typically find or create a user in your database
    return done(null, profile);
}
));

module.exports = passport;