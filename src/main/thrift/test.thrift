namespace java thrift

exception PlugException
{
  1:string msg
}

service PluggableSecurityTest
{
  bool ping();
  binary authenticate(1:binary token) throws (1:PlugException plugException)
  bool nonauthenticateoperation(1:binary token, 2:string operationRelatedData) throws (1:PlugException pe)
  string authenticationClass()
}