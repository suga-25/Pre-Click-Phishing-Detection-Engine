DROP TABLE IF EXISTS messages;

CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL
);

-- Case 1: 1 URL Detected
INSERT INTO messages (sender, subject, body) VALUES (
    'security-alert@verify-account-update.com',
    'Urgent: Account Suspended',
    'Dear user, your account requires immediate verification. Please visit https://amazon-security-check.xyz/login to fix this.'
);

-- Case 2: 3 URLs Detected
INSERT INTO messages (sender, subject, body) VALUES (
    'newsletter@techdaily.io',
    'Weekly Tech Digest',
    'Check out the new trends at https://techdaily.io/news and view our updates here https://github.com/trending or read our blog http://subdomain.example-blog.org/article?id=99'
);

-- Case 3: 0 URLs Detected (Edge Case)
INSERT INTO messages (sender, subject, body) VALUES (
    'info@company.com',
    'Internal Company Update',
    'Hello team, please remember that the office will remain closed this coming Friday. No action is required.'
);