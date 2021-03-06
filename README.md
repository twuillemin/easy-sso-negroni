# EasySSO
EasySSO is a simple, but nonetheless efficient go package to integrate a Single Sign-On in your application. EasySSO is compose of the following projects:

 * [easy-sso-common](https://github.com/twuillemin/easy-sso-common): the common definition and structures used by all the sub-projects
 * [easy-sso](https://github.com/twuillemin/easy-sso): the SSO server component. Along with the server this project also include components for services (validating the query) and client (authenticating and connecting to the services). These components only rely on the Go default http.
 * [easy-sso-mux](https://github.com/twuillemin/easy-sso-mux): a middleware for the [gorilla/mux](https://github.com/gorilla/mux) router, validating client authentication.
 * [easy-sso-negroni](https://github.com/twuillemin/easy-sso-negroni): a middleware for the [Negroni](https://github.com/urfave/negroni) web middleware, validating client authentication.


# EasySSO Negroni
This package is a middleware for the Negroni middleware pipeline. Negroni is a widely used Go package offering
a lot of nice features for creating middleware pipelines. In particular, Negroni offers a system of "middleware". 
Middlewares are function that are executed for each query in a pipeline.

As EasySSO is providing SSO feature, it makes total sense to have a middleware for Negroni that can validate the
authentication of a query and extract information that could be subsequently used by the endpoint.

# Usage
## Creating the middleware
Before being used the EasySSO Negroni must be created. The creation is done by using the function `ssomiddleware.New()`. 
This function takes a single parameter which is the public key used to very the signature of the SSO server. The public
must be given as a PEM file.

Example
```go
// Create a new instance of the middleware
authenticationMiddleware, err := ssomiddleware.New("publicKeyFileName.pub")
if err != nil {
    log.Fatal(err)
}
```

Alternatively, it exists the function `ssomiddleware.NewWithDetailedLogs()` which will add a lot of logs. Due to the 
volume of logs that can be generated on real server, this creator should probably be only used in test/dev environments

## Adding the middleware
For adding the middleware, simply use the function `ssomiddleware.Middleware` as a parameter to the standard gorilla/mux `Use` function

```go
// Create a new standard HTTP multiplexer
mux := http.NewServeMux()
mux.HandleFunc("/", simpleHandler)

// Create a new Negroni instance with EasySSO middleware
n := negroni.New()
n.Use(authenticationMiddleware)
n.UseHandler(mux)
```

Once the middleware is added, any query with a bad authentication will be rejected.

## Getting the authentication information
The authentication are stored in the request `Context`. However the package EasySSO Mux offers a simple function for
retrieving them `ssomiddleware.GetSsoAuthentication()`. This function returns a pointer to a structure having three 
attributes:


Name     |  Type    | Description
-------- | -------- | -------------------------------------------------------------------
`User`   | string   | The name of the user
`Roles`  | []string | The roles of the user
`Token`  | string   | The full token that can be re-used for sending to another service

Example:

```go
func helloHandler(w http.ResponseWriter, r *http.Request) {

	authentication, err := ssomiddleware.GetSsoAuthentication(r)
	if err != nil {
		log.Fatal("helloHandler: Unable to do get the authentication information", err)
	}

	w.Write([]byte("Hello " + authentication.User))
}
```

A fully working example is provided with the project.

# License

Copyright 2018 Thomas Wuillemin  <thomas.wuillemin@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this project or its content except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.