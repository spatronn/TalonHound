UPDATE ioc_items
SET observable_type = 'url'
WHERE observable_type = 'domain'
  AND observable LIKE '%/%';
