package hysteria2

import "net/http"

func(r *inboundRuntime)wrapHTTPHandler(handler http.Handler)http.Handler{
 if handler==nil{handler=http.NotFoundHandler()}
 return http.HandlerFunc(func(w http.ResponseWriter,request *http.Request){
  owned,release,err:=r.enter(request.Context())
  if err!=nil{w.WriteHeader(http.StatusServiceUnavailable);return}
  defer release()
  handler.ServeHTTP(w,request.WithContext(owned))
 })
}
