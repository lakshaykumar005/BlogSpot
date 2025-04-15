const express = require('express');
const router = express.Router();
const passport = require('passport');

// Regular login route
router.post('/login', (req, res, next) => {
  // Add your authentication logic here
  // This is just a placeholder - you'll need to implement proper authentication
  const { username, password } = req.body;
  
  if (username && password) {
    // Successful login
    req.session.user = { username };
    return res.redirect('/dashboard');
  } else {
    // Failed login
    return res.render('login', { error: 'Invalid credentials' });
  }
});

// Google OAuth routes
router.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication
    res.redirect('/dashboard');
  }
);

// Logout route
router.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

module.exports = router;