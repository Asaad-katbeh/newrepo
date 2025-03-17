// server.js
const express = require("express");
const app = express();
const port = 3000;

// Parse incoming request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/search", (req, res) => {
  const name = req.query.name; // Unsanitized user input
  // Simulated vulnerable SQL query using string concatenation
  const query = "SELECT * FROM users WHERE name = '" + name + "'";
  // For demonstration, we simply return the constructed query
  res.send(`Executing query: ${query}`);
});

app.get("/echo", (req, res) => {
  const message = req.query.message; // Unsanitized input
  // Vulnerable to XSS if the message contains malicious HTML/JavaScript
  res.send(`<html><body><h1>User Message</h1><p>${message}</p></body></html>`);
});

app.get("/calculate", (req, res) => {
  const expression = req.query.expr; // User-provided expression
  try {
    // DANGEROUS: eval is used on unsanitized input
    const result = eval(expression);
    res.send(`Result: ${result}`);
  } catch (error) {
    res.status(400).send("Invalid expression");
  }
});

app.listen(port, () => {
  console.log(
    `Vulnerable Express server listening at http://localhost:${port}`
  );
});
