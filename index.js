import bodyParser from "body-parser";
import express from "express";
import methodOverride from "method-override";
import path from "path";
import pkg from 'pg';
import { fileURLToPath } from "url";
import session from 'express-session';
import passport from 'passport';
import GoogleStrategy from 'passport-google-oauth20';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
dotenv.config();

const { Pool } = pkg;
const saltRounds = 10;

// PostgreSQL config
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || connectionString,
  ssl: { rejectUnauthorized: false },
  max: 20, // maximum number of clients in the pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Create tables if they don't exist
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100),
        google_id VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS blogs (
        id SERIAL PRIMARY KEY,
        btitle VARCHAR(200) NOT NULL,
        bblog TEXT NOT NULL,
        btime TIMESTAMP NOT NULL,
        user_id INTEGER NOT NULL REFERENCES users(id),
        bname VARCHAR(100) NOT NULL
      )
    `);
    
    console.log('Database tables ready');
  } catch (err) {
    console.error('Error setting up database tables:', err);
  }
})();

// Express app setup
const app = express();
const port = 3000;
const BLOGS_PER_PAGE = 5;
// EJS setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Middleware setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(methodOverride("_method"));
// Set default view variables for all templates
app.use((req, res, next) => {
  res.locals.showSearch = true; // Show search by default
  res.locals.searchQuery = null; // No search query by default
  res.locals.user = req.user || null; // User data if available
  next();
});
// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Passport Google OAuth configuration
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/auth/google/callback',
  passReqToCallback: true
},
async (req, accessToken, refreshToken, profile, done) => {
  try {
    // Check if user exists by google_id
    const userResult = await pool.query(
      "SELECT * FROM users WHERE google_id = $1",
      [profile.id]
    );

    if (userResult.rows.length > 0) {
      return done(null, userResult.rows[0]);
    }

    // Check if email exists
    const emailResult = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [profile.emails[0].value]
    );

    if (emailResult.rows.length > 0) {
      // Update existing user with google_id
      await pool.query(
        "UPDATE users SET google_id = $1 WHERE email = $2",
        [profile.id, profile.emails[0].value]
      );
      return done(null, emailResult.rows[0]);
    }

    // Create new user
    const newUser = await pool.query(
      "INSERT INTO users (username, email, google_id) VALUES ($1, $2, $3) RETURNING *",
      [profile.displayName, profile.emails[0].value, profile.id]
    );

    return done(null, newUser.rows[0]);
  } catch (err) {
    console.error('Google auth error:', err);
    return done(err);
  }
}));

// Passport serialization/deserialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err);
  }
});

// Middleware to make user available to all views
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  next();
});

// Middleware to check blog ownership
const checkBlogOwnership = async (req, res, next) => {
  try {
    const blog = await pool.query(
      "SELECT * FROM blogs WHERE id = $1 AND user_id = $2",
      [req.params.id, req.user.id]
    );
    if (blog.rows.length === 0) {
      return res.status(403).send("Unauthorized");
    }
    next();
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
};

// Middleware to add current timestamp
function addTimestamp(req, res, next) {
  req.body.timestamp = new Date().toISOString();
  next();
}

// Middleware to check if user is authenticated
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

// Routes
app.get("/", (req, res) => {
  res.render("index.ejs");
});

// Auth routes
app.get("/login", (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/ourblog');
  }
  res.render("login.ejs", { error: null });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.render("login.ejs", { error: "Invalid credentials" });
    }

    const user = result.rows[0];
    
    if (!user.password) {
      return res.render("login.ejs", { 
        error: "Please sign in with Google" 
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.render("login.ejs", { error: "Invalid credentials" });
    }

    req.login(user, (err) => {
      if (err) {
        return res.render("login.ejs", { error: "Error logging in" });
      }
      return res.redirect("/ourblog");
    });
  } catch (err) {
    console.error(err);
    res.render("login.ejs", { error: "Error logging in" });
  }
});

app.get("/signup", (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/ourblog');
  }
  res.render("signup.ejs", { error: null });
});

app.post("/signup", async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;
  
  if (password !== confirmPassword) {
    return res.render("signup.ejs", { error: "Passwords do not match" });
  }

  try {
    const userCheck = await pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $2",
      [username, email]
    );

    if (userCheck.rows.length > 0) {
      return res.render("signup.ejs", { 
        error: "Username or email already exists" 
      });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
      [username, email, hashedPassword]
    );

    req.login(newUser.rows[0], (err) => {
      if (err) {
        return res.render("signup.ejs", { error: "Error creating account" });
      }
      return res.redirect("/ourblog");
    });
  } catch (err) {
    console.error(err);
    res.render("signup.ejs", { error: "Error creating account" });
  }
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/ourblog');
  }
);

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
});

// Static pages
app.get("/contact", (req, res) => res.render("contact.ejs"));
app.get("/privacy", (req, res) => res.render("privacy.ejs"));
app.get("/about", (req, res) => res.render("about.ejs"));

// Blog routes
app.get("/ourblog", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const offset = (page - 1) * BLOGS_PER_PAGE;
    const searchQuery = req.query.q;
    
    let query, countQuery, queryParams;
    
    if (searchQuery) {
      // Search query
      query = `
        SELECT blogs.*, users.username 
        FROM blogs 
        JOIN users ON blogs.user_id = users.id 
        WHERE btitle ILIKE $1 OR bblog ILIKE $1 OR users.username ILIKE $1
        ORDER BY blogs.id DESC
        LIMIT $2 OFFSET $3
      `;
      countQuery = `
        SELECT COUNT(*) 
        FROM blogs 
        JOIN users ON blogs.user_id = users.id 
        WHERE btitle ILIKE $1 OR bblog ILIKE $1 OR users.username ILIKE $1
      `;
      queryParams = [`%${searchQuery}%`, BLOGS_PER_PAGE, offset];
    } else {
      // Regular query
      query = `
        SELECT blogs.*, users.username 
        FROM blogs 
        JOIN users ON blogs.user_id = users.id 
        ORDER BY blogs.id DESC
        LIMIT $1 OFFSET $2
      `;
      countQuery = 'SELECT COUNT(*) FROM blogs';
      queryParams = [BLOGS_PER_PAGE, offset];
    }
    
    // Get blogs for current page
    const result = await pool.query(query, queryParams);
    
    // Get total count of blogs
    const countResult = await pool.query(
      searchQuery ? countQuery : countQuery, 
      searchQuery ? [`%${searchQuery}%`] : []
    );
    const totalBlogs = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalBlogs / BLOGS_PER_PAGE);
    
    // Helper function for pagination URLs
    const paginationUrl = (pageNum) => {
      const url = new URL(`${req.protocol}://${req.get('host')}${req.originalUrl.split('?')[0]}`);
      if (searchQuery) url.searchParams.set('q', searchQuery);
      url.searchParams.set('page', pageNum);
      return url.pathname + url.search;
    };
    
    res.render("ourblog.ejs", { 
      blogsdata: result.rows,
      currentUser: req.user,
      currentPage: page,
      totalPages,
      paginationUrl,
      searchQuery
    });
  } catch (err) {
    console.error(err);
    res.status(500).render("error.ejs", { message: "Error loading blogs" ,
      showSearch: false,
      searchQuery: null
    });
  }
});
app.get("/search", (req, res) => {
  res.redirect(`/ourblog?q=${encodeURIComponent(req.query.q)}`);
});
app.get("/create", ensureAuthenticated, (req, res) => {
  res.render("create.ejs", { user: req.user });
});

app.post("/submit", ensureAuthenticated, async (req, res) => {
  const { title, blog } = req.body;
  
  if (!title || !blog) {
    return res.status(400).render("error.ejs", { message: "Title and content are required" });
  }

  try {
    await pool.query(
      "INSERT INTO blogs (btitle, bblog, btime, user_id, bname) VALUES ($1, $2, $3, $4, $5)",
      [title, blog, new Date().toISOString(), req.user.id, req.user.username]
    );
    res.redirect("/ourblog");
  } catch (err) {
    console.error(err);
    res.status(500).render("error.ejs", { message: "Error saving blog",
      showSearch: false,
      searchQuery: null
     });
  }
});

app.get("/edit/:id", ensureAuthenticated, checkBlogOwnership, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM blogs WHERE id = $1", [req.params.id]);
    res.render("edit.ejs", { blogsdata: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).render("error.ejs", { message: "Error loading blog",
      showSearch: false,
      searchQuery: null
     });
  }
});

app.put("/update/:id", ensureAuthenticated, checkBlogOwnership, async (req, res) => {
  const { title, blog } = req.body;
  
  try {
    await pool.query(
      "UPDATE blogs SET btitle = $1, bblog = $2 WHERE id = $3",
      [title, blog, req.params.id]
    );
    res.redirect("/ourblog");
  } catch (err) {
    console.error(err);
    res.status(500).render("error.ejs", { message: "Error updating blog",
      showSearch: false,
      searchQuery: null
     });
  }
});

app.get("/delete/:id", ensureAuthenticated, checkBlogOwnership, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM blogs WHERE id = $1", [req.params.id]);
    res.render("delete.ejs", { blogsdata: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).render("error.ejs", { message: "Error loading blog" ,
      showSearch: false,
      searchQuery: null
    });
  }
});

app.delete("/delete/:id", ensureAuthenticated, checkBlogOwnership, async (req, res) => {
  try {
    await pool.query("DELETE FROM blogs WHERE id = $1", [req.params.id]);
    res.redirect("/ourblog");
  } catch (err) {
    console.error(err);
    res.status(500).render("error.ejs", { message: "Error deleting blog" ,
      showSearch: false,
      searchQuery: null
    });
  }
});

app.get("/view/:id", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT blogs.*, users.username 
      FROM blogs 
      JOIN users ON blogs.user_id = users.id 
      WHERE blogs.id = $1
    `, [req.params.id]);
    
    if (result.rows.length === 0) {
      return res.status(404).render("error.ejs", { message: "Blog not found" ,
        showSearch: false,
        searchQuery: null
      });
    }
    
    res.render("view.ejs", { blog: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).render("error.ejs", { message: "Error loading blog",
      showSearch: false,
      searchQuery: null
     });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render("error.ejs", { 
    message: "Something went wrong",
    error: process.env.NODE_ENV === 'development' ? err : null,
    showSearch: false,
    searchQuery: null
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});