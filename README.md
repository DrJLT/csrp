# csrp

This is a version of https://github.com/DrJLT/csrf with more flexibility in usage. It supports httprouter.Handle and is supposed to be used in select routers only.

It is an ultra-light CSRF protection.

To be used as
```
router.POST("/protected", csrp.CSRF(protectedHandle))
router.POST("/unprotected", unprotectedHandle)
```
in the route definition.

To get the token, use
```
csrp.Token(w http.ResponseWriter, r *http.Request) string
```
