# Drupal 7 Hash Checker

Rewritten in C# so I can migrate Drupal 7 logins to a Blazor application.

Simply call the `checkpass` function with the plaintext password and the password hash.
If the plaintext password and the hash match, it will return `true`.

I've only written this with support for SHA512, maybe I'll write it with support for MD5 in the future.
