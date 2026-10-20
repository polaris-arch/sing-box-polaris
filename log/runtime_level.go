package log

import "errors"

// PrepareRuntimeLevel accepts only the concrete built-in factories whose
// publication operation is a nonblocking atomic store (or the disabled no-op).
// It never invokes an arbitrary external Factory callback during publication.
func PrepareRuntimeLevel(factory Factory, value string) (func(), error) {
 level := LevelTrace
 if value != "" { var err error; level,err=ParseLevel(value);if err!=nil{return nil,err} }
 switch f:=factory.(type) {
 case *defaultFactory:
  if f==nil{return nil,errors.New("missing log factory")}
  return func(){f.level.Store(int32(level))},nil
 case *nopFactory:
  return func(){},nil
 default:
  return nil,errors.New("custom logger has no runtime level publication contract")
 }
}
