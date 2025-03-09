---
title: "SQl-Injection"
date: 2025-03-07
draft: false
description: "Intro To Sql Injections"
tags: ["web", "hacking", "Server", "web"]
---
- Very common vulnerability in web applications is a `SQL Injection` vulnerability. Similarly to a Command Injection vulnerability, this vulnerability may occur when the web application executes a SQL query, including a value taken from user-supplied input.

- For example, in the `database` section, we saw an example of how a web application would use user-input to search within a certain table, with the following line of code:

```php
$query = "select * from users where name like '%$searchInput%'";
```

- If the user input is not properly filtered and validated (as is the case with `Command Injections`), we may execute another SQL query alongside this query, which may eventually allow us to take control over the database and its hosting server.

- For example, the same previous `College Management System 1.2` suffers from a SQL injection [vulnerability](https://www.exploit-db.com/exploits/47388), in which we can execute another `SQL` query that always returns `true`, meaning we successfully authenticated, which allows us to log in to the application. We can use the same vulnerability to retrieve data from the database or even gain control over the hosting server.
