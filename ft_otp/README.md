# ft_otp

## Summary

In this project, the aim is to implement a TOTP (Time-based One-Time Password)
system, which will be capable of generating ephemeral passwords from a master key.
It will be based on the RFC: <https://datatracker.ietf.org/doc/html/rfc6238>, so
you could use it in your day to day.

## Useful Commands

Compare output with oathtool:

```shell
oathtool --totp $(cat key.hex)
```
