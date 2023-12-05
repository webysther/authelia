---
title: "Identity Validation"
description: "Identity Validation Configuration"
lead: "Authelia uses multiple methods to verify the identity of users to prevent a malicious user from performing actions on behalf of them. This section describes these methods."
date: 2023-11-20T21:28:38+11:00
draft: false
images: []
menu:
  configuration:
    parent: "identity-validation"
weight: 105100
toc: true
---

## Configuration

{{< config-alert-example >}}

```yaml
identity_validation:
  elevated_session:
    expiration: '5 minutes'
    elevation_expiration: '10 minutes'
    characters: 8
    require_second_factor: false
    skip_second_factor: false
  reset_password:
    expiration: '5 minutes'
    jwt_algorithm: 'HS256'
    jwt_secret: ''
```

## Options

The two areas protected by the validation methods are:

- [Elevated Session](elevated-session.md) which prevents a logged in user from performing privileged actions without
  first proving their identity.
- [Reset Password](reset-password.md) which prevents an anonymous user from performing the password reset for a user
  without first proving their identity.
