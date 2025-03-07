package main

func main() {
	//mux := http.NewServeMux()
	//
	//transport := &http.Transport{
	//	TLSClientConfig: &tls.Config{
	//		ServerName:         os.Getenv("APP.NAME"),
	//		InsecureSkipVerify: true, // IMPORTANT!
	//	},
	//}
	//authenticator, err := pivereduware.NewAuthenticator(transport)
	//if err != nil {
	//
	//	os.Exit(1)
	//}
	//piverwareMiddleware := pivereduware.New()
	//
	//// Replace and use the service name from the generated proto file
	//piverwareMiddleware.EnableConnectRpcReflection(mux, "")
	//
	//// Auth interceptors should be attached to the service handler
	//interceptors := connect.WithInterceptors(
	//	piverwareMiddleware.UnaryAuthTokenValidatorInterceptor(authenticator, []string{}),
	//	piverwareMiddleware.LoggingUnaryInterceptor(),
	//	piverwareMiddleware.TenantHeaderInterceptor([]string{}),
	//)
}
