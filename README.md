# steam_guard
Is used to easily get steam guards authentication code.
provided you have the shared secret
#### Usage:
```
extern crate steam_guard;
let secret = "123123123Ab=";
println!("Expires in:{}s", steam_guard::expires_in_sec());
println!("Login with:{}", steam_guard::from_secret(secret));
println!("Next login code:{}", steam_guard::from_secret_future(secret, 1));

```
